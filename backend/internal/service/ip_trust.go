package service

// IP 透传（X-Forwarded-For）配置治理。
//
// 背景：NewAPI 用 Gin 的 c.ClientIP() 写 logs.ip（newapi 源码 model/log.go）。
// Gin 只有在「直连对端命中可信代理列表」时才解析 X-Forwarded-For，否则直接把
// 直连对端的地址当客户端 IP。NewAPI 的 TRUSTED_PROXIES 未显式配置时只信任
// 回环 / RFC1918 / fc00::/7（newapi 源码 common/trusted_proxies.go）。
// 于是「站点套了公网 CDN」这种最常见部署下，CDN 节点回源是公网地址 → 不在可信
// 列表 → XFF 被整个丢弃 → logs.ip 全是 CDN 回源 IP。
//
// 本文件只做两件事，都不碰 NewAPI 源码：
//  1. 解析 / 校验用户填写的 TRUSTED_PROXIES（拒绝会击穿鉴权的过宽网段）；
//  2. 生成可重复渲染的 .env 标记块与 compose 覆盖层内容。
//
// 是否真正写入文件、是否重启 NewAPI 由 install.sh 负责，后端只做纯计算，
// 这样同一份规则可以被 shell 与 Go 两侧共同验证。

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// TrustedProxiesDotEnvBegin / End 是 .env 中由本工具接管的标记块边界。
// 使用标记块而不是直接改写 TRUSTED_PROXIES= 这一行，原因有二：
//   - 用户的 .env 里该行常被注释（# TRUSTED_PROXIES=...），直接替换易误伤；
//   - 标记块可以整体重渲染，天然幂等，多次运行不会累积重复行。
const (
	TrustedProxiesDotEnvBegin = "# >>> newapi-tools: TRUSTED_PROXIES (managed block) >>>"
	TrustedProxiesDotEnvEnd   = "# <<< newapi-tools: TRUSTED_PROXIES <<<"
)

// TrustedProxiesOverlayFile 是 compose 覆盖层文件名，落在 NewAPI 目录下。
const TrustedProxiesOverlayFile = "docker-compose.trusted-proxies.yml"

// TrustedProxiesNone 对应 NewAPI 的严格模式：不信任任何代理。
const TrustedProxiesNone = "none"

// defaultLoopbackProxy 是 NewAPI 前面还有一层本机 nginx 时最常需要的那一项。
// 注意 NewAPI 的语义是「显式列表完全替代默认值」，一旦写了自定义列表，默认
// 的回环信任就没了，因此这一项必须由本工具主动补上。
const defaultLoopbackProxy = "127.0.0.1/32"

// TrustedProxiesInput 描述用户为 NewAPI 填写的可信代理来源。
type TrustedProxiesInput struct {
	// Entries 是用户粘贴的原始条目（IP 或 CIDR），允许空字符串元素与空白。
	Entries []string
	// IncludeLoopback 表示 NewAPI 前面还有一层本机（或同机容器）反向代理，
	// 需要把 127.0.0.1/32 一并加入可信列表。
	IncludeLoopback bool
}

// TrustedProxiesResult 是解析校验后的结果。
type TrustedProxiesResult struct {
	// Value 是可直接写入 TRUSTED_PROXIES 的值（逗号分隔，已去重去空白）。
	Value string
	// Effective 是本次最终生效的条目，保持稳定顺序便于比对与展示。
	Effective []string
	// Warnings 是「能配置但值得提醒」的情况，不阻塞写入。
	Warnings []string
	// Dropped 是被丢弃的重复条目数量，仅用于提示。
	Dropped int
}

// ErrTrustedProxiesEmpty 表示没有任何可用条目。
var ErrTrustedProxiesEmpty = errors.New("至少需要一个可信代理 IP 或 CIDR")

// ErrTrustedProxiesTooBroad 表示某个条目会信任过宽的地址空间。
var ErrTrustedProxiesTooBroad = errors.New("TRUSTED_PROXIES 包含过宽地址段，会允许任意客户端伪造 X-Forwarded-For")

// ErrTrustedProxiesNoneMixed 表示 none 与其他条目混用。
var ErrTrustedProxiesNoneMixed = errors.New("TRUSTED_PROXIES=none 必须单独使用")

// ErrTrustedProxiesInvalid 表示条目不是合法 IP / CIDR。
var ErrTrustedProxiesInvalid = errors.New("TRUSTED_PROXIES 含非法 IP 或 CIDR")

// BuildTrustedProxies 解析并校验用户输入，产出可直接写入 NewAPI 的配置值。
//
// 校验规则来自 NewAPI 侧的两条硬约束：
//   - 该值决定 c.ClientIP() 是否采信 X-Forwarded-For；
//   - model/token 的 IP 白名单鉴权（newapi 源码 middleware/auth.go）用的正是
//     c.ClientIP() 的结果。
//
// 因此「广播级网段」在这里必须被拒绝：填 0.0.0.0/0 等于把伪造 IP 的权限开给
// 全网，会直接击穿 token 的 IP 白名单。
func BuildTrustedProxies(in TrustedProxiesInput) (*TrustedProxiesResult, error) {
	raw := make([]string, 0, len(in.Entries)+1)
	for _, entry := range in.Entries {
		for _, part := range strings.Split(entry, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				raw = append(raw, trimmed)
			}
		}
	}

	hasNone := false
	for _, item := range raw {
		if strings.EqualFold(item, TrustedProxiesNone) {
			hasNone = true
		}
	}
	if hasNone {
		if len(raw) > 1 || in.IncludeLoopback {
			return nil, ErrTrustedProxiesNoneMixed
		}
		return &TrustedProxiesResult{Value: TrustedProxiesNone, Effective: []string{TrustedProxiesNone}}, nil
	}

	if in.IncludeLoopback {
		raw = append(raw, defaultLoopbackProxy)
	}

	seen := make(map[string]struct{}, len(raw))
	effective := make([]string, 0, len(raw))
	warnings := make([]string, 0, 2)
	dropped := 0

	for _, item := range raw {
		prefix, isSingleIP, err := parseProxyEntry(item)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrTrustedProxiesInvalid, item)
		}
		if isBroadcastPrefix(prefix) {
			return nil, fmt.Errorf("%w: %s", ErrTrustedProxiesTooBroad, item)
		}
		if isSingleIP && prefix.Bits() == prefix.Addr().BitLen() {
			switch {
			case prefix.Addr().IsLoopback():
				warnings = append(warnings, "可信代理包含回环地址，若该层代理不在本机请确认是否必要")
			case isPubliclyRoutable(prefix.Addr()):
				warnings = append(warnings, fmt.Sprintf("可信代理包含公网单地址 %s，请确认它确实是你的代理/CDN 节点", prefix.Addr()))
			}
		}
		key := prefix.String()
		if _, ok := seen[key]; ok {
			dropped++
			continue
		}
		seen[key] = struct{}{}
		effective = append(effective, key)
	}

	if len(effective) == 0 {
		return nil, ErrTrustedProxiesEmpty
	}

	sort.SliceStable(effective, func(i, j int) bool {
		return effective[i] < effective[j]
	})

	return &TrustedProxiesResult{
		Value:     strings.Join(effective, ","),
		Effective: effective,
		Warnings:  warnings,
		Dropped:   dropped,
	}, nil
}

// parseProxyEntry 把一条用户输入规范成 netip.Prefix。
// 裸 IP 会被补成 /32（IPv4）或 /128（IPv6），与 NewAPI 侧 gin.SetTrustedProxies
// 对裸 IP 的处理保持一致。
func parseProxyEntry(entry string) (netip.Prefix, bool, error) {
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, false, err
		}
		return prefix.Masked(), false, nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), true, nil
}

// isBroadcastPrefix 判定该网段是否等于「整个地址空间」。
// 只拦 /0，不额外猜测用户的 CDN 段大小：合法的 CDN 回源段跨度不确定，
// 过度收紧会误伤真实配置。
func isBroadcastPrefix(prefix netip.Prefix) bool {
	return prefix.Bits() == 0
}

// isPubliclyRoutable 判断是否为公网可路由地址（用于给提示而非拦截）。
func isPubliclyRoutable(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if addr.Is6() && addr.Is4In6() {
		return isPubliclyRoutable(addr.Unmap())
	}
	return true
}

// TrustedProxiesDotEnvBlock 渲染 .env 中由本工具接管的整段内容（含换行）。
// 调用方应「先删旧块再追加新块」，以保证幂等。
func TrustedProxiesDotEnvBlock(value string) string {
	var b strings.Builder
	b.WriteString(TrustedProxiesDotEnvBegin)
	b.WriteString("\n")
	b.WriteString("# 由 new_api_tools 生成。作用是让 NewAPI(Gin) 采信 CDN 回源带来的\n")
	b.WriteString("# X-Forwarded-For，从而把真实用户 IP 写入 logs.ip。\n")
	b.WriteString("# 手工维护此块会被下次「IP 透传体检」覆盖。\n")
	b.WriteString("TRUSTED_PROXIES=")
	b.WriteString(value)
	b.WriteString("\n")
	b.WriteString(TrustedProxiesDotEnvEnd)
	b.WriteString("\n")
	return b.String()
}

// TrustedProxiesOverlayYAML 渲染 compose 覆盖层内容。
// 覆盖层的作用是「.env 被上游模板覆盖后仍有一条兜底路径」：用户更新 NewAPI 时
// 只要沿用带 -f 的命令，配置就还在。它不能替代 .env，只作为第二落点。
func TrustedProxiesOverlayYAML(serviceName, value string) string {
	if serviceName == "" {
		serviceName = "new-api"
	}
	var b strings.Builder
	b.WriteString("# 由 new_api_tools 生成，用于 NewAPI 的 IP 透传（X-Forwarded-For）。\n")
	b.WriteString("# 更新 NewAPI 时请沿用：\n")
	b.WriteString("#   docker compose -f docker-compose.yml -f ")
	b.WriteString(TrustedProxiesOverlayFile)
	b.WriteString(" up -d\n")
	b.WriteString("# 若只跑 docker compose up -d，则依赖 .env 中同名的 TRUSTED_PROXIES。\n")
	b.WriteString("services:\n")
	b.WriteString("  ")
	b.WriteString(serviceName)
	b.WriteString(":\n")
	b.WriteString("    environment:\n")
	b.WriteString("      TRUSTED_PROXIES: \"${TRUSTED_PROXIES:-")
	b.WriteString(strings.ReplaceAll(value, "\"", ""))
	b.WriteString("}\"\n")
	return b.String()
}

// TrustedProxiesStatus 描述 NewAPI 当前的可信代理配置状态。
type TrustedProxiesStatus string

const (
	// TrustedProxiesStatusMissing：未设置 → NewAPI 用回环 + 私网默认值，CDN 公网回源时 XFF 被丢弃。
	TrustedProxiesStatusMissing TrustedProxiesStatus = "missing"
	// TrustedProxiesStatusNone：显式 none → 不信任任何代理由，同样拿不到真实 IP。
	TrustedProxiesStatusNone TrustedProxiesStatus = "none"
	// TrustedProxiesStatusConfigured：已设置自定义列表。
	TrustedProxiesStatusConfigured TrustedProxiesStatus = "configured"
	// TrustedProxiesStatusInvalid：已设置但内容无法解析。
	TrustedProxiesStatusInvalid TrustedProxiesStatus = "invalid"
)

// ClassifyTrustedProxies 把 NewAPI 容器里读到的 TRUSTED_PROXIES 原始值分类。
// 传入空字符串表示该环境变量不存在。
func ClassifyTrustedProxies(raw string) (TrustedProxiesStatus, []string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return TrustedProxiesStatusMissing, nil
	}
	if strings.EqualFold(trimmed, TrustedProxiesNone) {
		return TrustedProxiesStatusNone, nil
	}
	entries := make([]string, 0, 4)
	for _, part := range strings.Split(trimmed, ",") {
		if item := strings.TrimSpace(part); item != "" {
			entries = append(entries, item)
		}
	}
	if len(entries) == 0 {
		return TrustedProxiesStatusInvalid, nil
	}
	for _, item := range entries {
		if _, _, err := parseProxyEntry(item); err != nil {
			return TrustedProxiesStatusInvalid, nil
		}
	}
	return TrustedProxiesStatusConfigured, entries
}

// TrustedProxiesContainsPublicPeer 判断在给定可信代理列表下，NewAPI 是否会采信
// 一个「来自公网地址」的直连对端所携带的 X-Forwarded-For。
//
// 这是判断「CDN 场景是否已修复」的核心依据：只有当至少一个公网网段被显式信任时，
// 公网 CDN 回源带来的 XFF 才会被采信。
func TrustedProxiesContainsPublicPeer(entries []string) bool {
	for _, item := range entries {
		prefix, _, err := parseProxyEntry(item)
		if err != nil {
			continue
		}
		if isPubliclyRoutable(prefix.Addr()) {
			return true
		}
	}
	return false
}

// SuggestedTrustedProxiesForCDN 给出一份常用 CDN 回源段的初始建议。
//
// 这些值只是「让用户少查一步文档」的起点，不是权威清单：CDN 厂商会调整回源
// 段，用户必须用厂商控制台里的实际值覆盖。返回的是可直接展示给用户的条目。
func SuggestedTrustedProxiesForCDN(vendor string) []string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "cloudflare":
		// Cloudflare 公布的 IPv4 回源段。
		return []string{
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
			"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
			"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		}
	default:
		return nil
	}
}
