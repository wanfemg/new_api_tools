package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/new-api-tools/backend/internal/config"
	"github.com/new-api-tools/backend/internal/database"
	"github.com/new-api-tools/backend/internal/logger"

	_ "modernc.org/sqlite"
)

const fingerprintQueryTimeout = 30 * time.Second

// DeviceFingerprintService 计算启发式「设备/身份指纹」（logs 只有 ip，无 UA/指纹字段），
// 并从本地 SQLite 快照表 user_device_snapshot 提供三个风控视图。
type DeviceFingerprintService struct {
	cfg   *config.Config
	db    *database.Manager // 主库（users/setting）
	logDB *database.Manager // 日志库（logs）
}

func NewDeviceFingerprintService() *DeviceFingerprintService {
	return &DeviceFingerprintService{
		cfg:   config.Get(),
		db:    database.Get(),
		logDB: database.GetLog(),
	}
}

// salt 从工具自身密钥派生，保证 hash 不可被离线反推 ip。
func (s *DeviceFingerprintService) salt() string {
	if s.cfg.JWTSecretKey != "" {
		return s.cfg.JWTSecretKey
	}
	return "newapi-tool-device-fp"
}

func fpHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

// deviceFP 设备指纹 = SHA256(salt + ip)，跨 token/账号关联同一网络出口。
func (s *DeviceFingerprintService) deviceFP(ip string) string {
	return fpHash(s.salt(), ip)
}

// identityFP 复合身份指纹 = SHA256(salt + ip + token_id + user_id)。
// 注意：它依赖 token_id，属于「(user, token, ip)」粒度，故按最近日志现算，不进快照表。
func (s *DeviceFingerprintService) identityFP(ip string, tokenID, userID int64) string {
	return fpHash(s.salt(), ip, strconv.FormatInt(tokenID, 10), strconv.FormatInt(userID, 10))
}

// ========== 本地 SQLite 快照 ==========

func (s *DeviceFingerprintService) snapshotPath() string {
	dataDir := strings.TrimSpace(s.cfg.DataDir)
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "fingerprint.db")
}

func (s *DeviceFingerprintService) openSnapshot() (*sql.DB, error) {
	path := s.snapshotPath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func (s *DeviceFingerprintService) ensureSnapshot(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_device_snapshot (
			user_id       INTEGER NOT NULL,
			ip            TEXT    NOT NULL,
			device_fp     TEXT    NOT NULL,
			geo_label     TEXT    NOT NULL DEFAULT '',
			country_code  TEXT    NOT NULL DEFAULT '',
			region        TEXT    NOT NULL DEFAULT '',
			city          TEXT    NOT NULL DEFAULT '',
			request_count INTEGER NOT NULL DEFAULT 0,
			first_seen    INTEGER NOT NULL DEFAULT 0,
			last_seen     INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, ip)
		);
		CREATE INDEX IF NOT EXISTS idx_uds_device_fp ON user_device_snapshot (device_fp);
		CREATE INDEX IF NOT EXISTS idx_uds_last_seen ON user_device_snapshot (last_seen);
	`)
	return err
}

// RebuildSnapshot 从 logs 覆盖式重建快照（type IN (2,5)、窗口内、ip 非空）。
// 返回写入的 (user_id, ip) 行数。
func (s *DeviceFingerprintService) RebuildSnapshot(ctx context.Context, windowSeconds int64) (int, error) {
	startTime := time.Now().Unix() - windowSeconds
	query := s.logDB.RebindQuery(`
		SELECT user_id, ip, COUNT(*) AS request_count, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
		FROM logs
		WHERE type IN (2,5) AND created_at >= ? AND ip IS NOT NULL AND ip <> '' AND user_id IS NOT NULL
		GROUP BY user_id, ip`)
	rows, err := s.logDB.QueryWithTimeout(fingerprintQueryTimeout, query, startTime)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	// 批量地理反查
	ipSet := map[string]bool{}
	for _, r := range rows {
		if ip := toString(r["ip"]); ip != "" {
			ipSet[ip] = true
		}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	geoAvailable := IsIPGeoAvailable()
	var geoMap map[string]IPGeoInfo
	if geoAvailable {
		geoMap = LookupIPGeoBatch(ips)
	}

	db, err := s.openSnapshot()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	if err := s.ensureSnapshot(ctx, db); err != nil {
		return 0, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO user_device_snapshot
			(user_id, ip, device_fp, geo_label, country_code, region, city, request_count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, ip) DO UPDATE SET
			device_fp = excluded.device_fp,
			geo_label = excluded.geo_label,
			country_code = excluded.country_code,
			region = excluded.region,
			city = excluded.city,
			request_count = excluded.request_count,
			first_seen = excluded.first_seen,
			last_seen = excluded.last_seen`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	written := 0
	for _, r := range rows {
		userID := toInt64(r["user_id"])
		ip := toString(r["ip"])
		if userID <= 0 || ip == "" {
			continue
		}
		info := IPGeoInfo{}
		if geoAvailable {
			info = geoMap[ip]
		}
		geoLabel := ""
		if geoAvailable {
			geoLabel = geoDisplayLabel(info)
		}
		if _, err := stmt.ExecContext(ctx,
			userID, ip, s.deviceFP(ip), geoLabel, info.CountryCode, info.Region, info.City,
			toInt64(r["request_count"]), toInt64(r["first_seen"]), toInt64(r["last_seen"])); err != nil {
			return written, err
		}
		written++
	}

	// 清理过期行（窗口外）
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_device_snapshot WHERE last_seen < ?`, startTime); err != nil {
		return written, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return written, nil
}

// recentIPRow 是用户列表「最近 IP/地理」列的返回单元。
type recentIPRow struct {
	IP        string   `json:"ip"`
	DeviceFP  string   `json:"device_fp"`
	GeoLabel  string   `json:"geo_label"`
	LastSeen  int64    `json:"last_seen"`
	RiskFlags []string `json:"risk_flags,omitempty"` // SAME_IP_MULTI_ACCOUNT / MULTI_IP_ACCOUNT
}

// GetRecentIPs 批量返回用户最近 IP（快照内按 last_seen 取最新一条），并标注风控标签。
func (s *DeviceFingerprintService) GetRecentIPs(userIDs []int64) (map[int64]recentIPRow, error) {
	result := map[int64]recentIPRow{}
	if len(userIDs) == 0 {
		return result, nil
	}
	db, err := s.openSnapshot()
	if err != nil {
		return result, err
	}
	defer db.Close()
	if err := s.ensureSnapshot(context.Background(), db); err != nil {
		return result, err
	}

	ph := make([]string, len(userIDs))
	args := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		ph[i] = "?"
		args[i] = id
	}
	in := strings.Join(ph, ",")

	// 1) 每用户最新 IP（按 last_seen 降序，首条即最新）
	rows, err := db.QueryContext(context.Background(), fmt.Sprintf(`
		SELECT user_id, ip, device_fp, geo_label, last_seen
		FROM user_device_snapshot WHERE user_id IN (%s)
		ORDER BY user_id, last_seen DESC`, in), args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var (
			userID   int64
			ip       string
			deviceFP string
			geoLabel string
			lastSeen int64
		)
		if err := rows.Scan(&userID, &ip, &deviceFP, &geoLabel, &lastSeen); err != nil {
			rows.Close()
			return result, err
		}
		if _, ok := result[userID]; ok {
			continue
		}
		result[userID] = recentIPRow{IP: ip, DeviceFP: deviceFP, GeoLabel: geoLabel, LastSeen: lastSeen}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return result, err
	}
	if len(result) == 0 {
		return result, nil
	}

	// 2) 每用户不同 IP 数 → MULTI_IP_ACCOUNT
	ipCountByUser := map[int64]int64{}
	ipRows, err := db.QueryContext(context.Background(), fmt.Sprintf(`
		SELECT user_id, COUNT(DISTINCT ip) AS ip_count
		FROM user_device_snapshot WHERE user_id IN (%s) GROUP BY user_id`, in), args...)
	if err == nil {
		for ipRows.Next() {
			var uid, cnt int64
			if ipRows.Scan(&uid, &cnt) == nil && cnt >= 2 {
				ipCountByUser[uid] = cnt
			}
		}
		ipRows.Close()
	}

	// 3) 设备指纹 → 关联账号数 → SAME_IP_MULTI_ACCOUNT
	fpSet := map[string]bool{}
	for _, r := range result {
		if r.DeviceFP != "" {
			fpSet[r.DeviceFP] = true
		}
	}
	multiAcctFP := map[string]bool{}
	if len(fpSet) > 0 {
		fps := make([]string, 0, len(fpSet))
		for fp := range fpSet {
			fps = append(fps, fp)
		}
		fpPh := make([]string, len(fps))
		fpArgs := make([]interface{}, len(fps))
		for i, fp := range fps {
			fpPh[i] = "?"
			fpArgs[i] = fp
		}
		fpRows, err := db.QueryContext(context.Background(), fmt.Sprintf(`
			SELECT device_fp, COUNT(DISTINCT user_id) AS user_count
			FROM user_device_snapshot WHERE device_fp IN (%s) GROUP BY device_fp`, strings.Join(fpPh, ",")), fpArgs...)
		if err == nil {
			for fpRows.Next() {
				var fp string
				var cnt int64
				if fpRows.Scan(&fp, &cnt) == nil && cnt >= 2 {
					multiAcctFP[fp] = true
				}
			}
			fpRows.Close()
		}
	}

	// 4) 打标签
	for uid, r := range result {
		flags := []string{}
		if multiAcctFP[r.DeviceFP] {
			flags = append(flags, "SAME_IP_MULTI_ACCOUNT")
		}
		if ipCountByUser[uid] >= 2 {
			flags = append(flags, "MULTI_IP_ACCOUNT")
		}
		r.RiskFlags = flags
		result[uid] = r
	}
	return result, nil
}

// GetSameIPMultiAccounts 同 IP 多账号（SAME_IP_MULTI_ACCOUNT）：同一 ip 下 ≥minUsers 个账号。
func (s *DeviceFingerprintService) GetSameIPMultiAccounts(window string, minUsers, limit int) (map[string]interface{}, error) {
	seconds, ok := WindowSeconds[window]
	if !ok {
		seconds = 86400
	}
	startTime := time.Now().Unix() - seconds

	wlCond, wlArgs := PanelWhitelistNotInClause("l.user_id")
	wlSQL := ""
	if wlCond != "" {
		wlSQL = " AND " + wlCond
	}
	query := s.logDB.RebindQuery(fmt.Sprintf(`
		SELECT l.ip, COUNT(DISTINCT l.user_id) AS user_count, COUNT(DISTINCT l.token_id) AS token_count, COUNT(*) AS request_count
		FROM logs l
		WHERE l.created_at >= ? AND l.type IN (2,5) AND l.ip IS NOT NULL AND l.ip <> ''%s
		GROUP BY l.ip
		HAVING COUNT(DISTINCT l.user_id) >= ?
		ORDER BY user_count DESC
		LIMIT ?`, wlSQL))

	qArgs := []interface{}{startTime}
	qArgs = append(qArgs, wlArgs...)
	qArgs = append(qArgs, minUsers, limit)
	rows, err := s.logDB.QueryWithTimeout(fingerprintQueryTimeout, query, qArgs...)
	if err != nil {
		return nil, err
	}

	items := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		ip := toString(r["ip"])
		item := map[string]interface{}{
			"ip":            ip,
			"device_fp":     s.deviceFP(ip),
			"user_count":    toInt64(r["user_count"]),
			"token_count":   toInt64(r["token_count"]),
			"request_count": toInt64(r["request_count"]),
		}
		if info := geoLabelForIP(ip); info != "" {
			item["geo_label"] = info
		}
		items = append(items, item)
	}

	return map[string]interface{}{"items": items, "total": len(items), "window": window, "min_users": minUsers}, nil
}

// GetSameAccountMultiIPs 同账号多 IP（MULTI_IP_ACCOUNT）：同一账号 ≥minIPs 个不同 IP。
func (s *DeviceFingerprintService) GetSameAccountMultiIPs(window string, minIPs, limit int) (map[string]interface{}, error) {
	seconds, ok := WindowSeconds[window]
	if !ok {
		seconds = 86400
	}
	startTime := time.Now().Unix() - seconds

	wlCond, wlArgs := PanelWhitelistNotInClause("l.user_id")
	wlSQL := ""
	if wlCond != "" {
		wlSQL = " AND " + wlCond
	}
	query := s.logDB.RebindQuery(fmt.Sprintf(`
		SELECT l.user_id, COALESCE(NULLIF(MAX(l.username), ''), '') AS username,
			COUNT(DISTINCT l.ip) AS ip_count, COUNT(*) AS request_count
		FROM logs l
		WHERE l.created_at >= ? AND l.type IN (2,5) AND l.ip IS NOT NULL AND l.ip <> ''%s
		GROUP BY l.user_id
		HAVING COUNT(DISTINCT l.ip) >= ?
		ORDER BY ip_count DESC
		LIMIT ?`, wlSQL))

	qArgs := []interface{}{startTime}
	qArgs = append(qArgs, wlArgs...)
	qArgs = append(qArgs, minIPs, limit)
	rows, err := s.logDB.QueryWithTimeout(fingerprintQueryTimeout, query, qArgs...)
	if err != nil {
		return nil, err
	}

	items := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]interface{}{
			"user_id":       toInt64(r["user_id"]),
			"username":      toString(r["username"]),
			"ip_count":      toInt64(r["ip_count"]),
			"request_count": toInt64(r["request_count"]),
		})
	}

	return map[string]interface{}{"items": items, "total": len(items), "window": window, "min_ips": minIPs}, nil
}

// GetUserDeviceFingerprint 返回用户详情「设备指纹」页签所需数据。
func (s *DeviceFingerprintService) GetUserDeviceFingerprint(userID int64) (map[string]interface{}, error) {
	// 最近一条日志 → 复合身份指纹
	latestQ := s.logDB.RebindQuery(`
		SELECT ip, token_id, created_at
		FROM logs
		WHERE user_id = ? AND type IN (2,5) AND ip IS NOT NULL AND ip <> ''
		ORDER BY created_at DESC
		LIMIT 1`)
	latest, err := s.logDB.QueryOneWithTimeout(fingerprintQueryTimeout, latestQ, userID)
	if err != nil {
		return nil, err
	}

	deviceFP := ""
	identityFP := ""
	latestIP := ""
	if latest != nil {
		latestIP = toString(latest["ip"])
		deviceFP = s.deviceFP(latestIP)
		identityFP = s.identityFP(latestIP, toInt64(latest["token_id"]), userID)
	}

	// 同设备账号（相同 device_fp 的其他 user_id）
	sameDevice := []map[string]interface{}{}
	if deviceFP != "" {
		sameDevice = s.sameDeviceAccounts(deviceFP, userID)
	}

	// 风险标签
	riskFlags := []string{}
	if len(sameDevice) > 0 {
		riskFlags = append(riskFlags, "SAME_IP_MULTI_ACCOUNT")
	}
	ipCount := s.userIPCount(userID)
	if ipCount >= 2 {
		riskFlags = append(riskFlags, "MULTI_IP_ACCOUNT")
	}

	return map[string]interface{}{
		"user_id":      userID,
		"latest_ip":    latestIP,
		"device_fp":    deviceFP,
		"identity_fp":  identityFP,
		"same_device":  sameDevice,
		"ip_count":     ipCount,
		"risk_flags":   riskFlags,
	}, nil
}

func (s *DeviceFingerprintService) sameDeviceAccounts(deviceFP string, excludeUserID int64) []map[string]interface{} {
	db, err := s.openSnapshot()
	if err != nil {
		logger.L.Warn("设备指纹快照打开失败: " + err.Error())
		return nil
	}
	defer db.Close()

	rows, err := db.QueryContext(context.Background(), `
		SELECT DISTINCT user_id FROM user_device_snapshot WHERE device_fp = ? AND user_id != ? LIMIT 20`, deviceFP, excludeUserID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return []map[string]interface{}{}
	}

	// 回主库补 username
	ph := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		ph[i] = s.db.Placeholder(i + 1)
		args[i] = id
	}
	q := fmt.Sprintf("SELECT id, username, display_name FROM users WHERE id IN (%s) AND deleted_at IS NULL", strings.Join(ph, ","))
	urows, err := s.db.Query(q, args...)
	if err != nil {
		return []map[string]interface{}{}
	}
	byID := map[int64]map[string]interface{}{}
	for _, ur := range urows {
		name := toString(ur["display_name"])
		if name == "" || name == "<nil>" {
			name = toString(ur["username"])
		}
		byID[toInt64(ur["id"])] = map[string]interface{}{"user_id": toInt64(ur["id"]), "username": name}
	}
	out := make([]map[string]interface{}, 0, len(ids))
	for _, id := range ids {
		if u, ok := byID[id]; ok {
			out = append(out, u)
		}
	}
	return out
}

func (s *DeviceFingerprintService) userIPCount(userID int64) int64 {
	query := s.logDB.RebindQuery(`
		SELECT COUNT(DISTINCT ip) AS ip_count FROM logs
		WHERE user_id = ? AND type IN (2,5) AND ip IS NOT NULL AND ip <> ''`)
	row, err := s.logDB.QueryOneWithTimeout(fingerprintQueryTimeout, query, userID)
	if err != nil || row == nil {
		return 0
	}
	return toInt64(row["ip_count"])
}

// geoLabelForIP 返回单个 IP 的地理展示标签（GeoIP 不可用则空）。
func geoLabelForIP(ip string) string {
	if !IsIPGeoAvailable() {
		return ""
	}
	return geoDisplayLabel(LookupIPGeo(ip))
}
