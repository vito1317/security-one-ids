<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use Symfony\Component\Process\Process;

/**
 * ISO 27001:2022 Annex A 合規自動化檢測。
 *
 * 此服務在本機執行一組可自動偵測的技術面檢查（Annex A Section 8 為主），
 * 將每項檢查對應到 ISO 27001 控制編號，並回傳統一結構的結果。
 * 不會修改系統狀態，純粹讀取。
 */
class ComplianceAnalyzer
{
    public const STATUS_PASS = 'pass';
    public const STATUS_FAIL = 'fail';
    public const STATUS_WARNING = 'warning';
    public const STATUS_NOT_APPLICABLE = 'not_applicable';

    public const SEV_CRITICAL = 'critical';
    public const SEV_HIGH = 'high';
    public const SEV_MEDIUM = 'medium';
    public const SEV_LOW = 'low';

    /**
     * 執行全部檢查並回傳完整報告。
     */
    public function run(): array
    {
        $checks = [
            $this->checkRootAccounts(),           // A.5.15 / A.8.2
            $this->checkPasswordPolicy(),         // A.5.17
            $this->checkSudoersNoPasswd(),        // A.8.2
            $this->checkShadowPermissions(),      // A.8.3
            $this->checkSshConfig(),              // A.8.5
            $this->checkMalwareProtection(),      // A.8.7
            $this->checkUnattendedUpgrades(),     // A.8.8
            $this->checkFileIntegrity(),          // A.8.9
            $this->checkLogging(),                // A.8.15
            $this->checkIdsIps(),                 // A.8.16
            $this->checkTimeSync(),               // A.8.17
            $this->checkFirewall(),               // A.8.20
            $this->checkDiskEncryption(),         // A.8.24
            $this->checkSshCiphers(),             // A.8.24
            $this->checkBackupEvidence(),         // A.8.13
            // Extended rule set:
            $this->checkFail2ban(),               // A.5.7
            $this->checkIdleSessionTimeout(),     // A.8.1
            $this->checkDiskCapacity(),           // A.8.6
            $this->checkInodeCapacity(),          // A.8.6
            $this->checkListeningServices(),      // A.8.21
            $this->checkKernelHardening(),        // A.8.9
            $this->checkTmpMountOptions(),        // A.8.9
            $this->checkEmptyPasswords(),         // A.5.16
            $this->checkWorldWritableCriticalFiles(), // A.8.3
            $this->checkSshKeyAuthPresence(),     // A.8.5
            $this->checkCronHygiene(),            // A.8.18
            $this->checkUnsignedAptSources(),     // A.8.19
            $this->checkDormantAccounts(),        // A.5.16
            $this->checkCoreDumpDisabled(),       // A.8.9
            $this->checkWebServerTlsProtocol(),   // A.8.24
            // Third wave:
            $this->checkAuditdRules(),            // A.5.28
            $this->checkSecureDeleteTools(),      // A.8.10
            $this->checkSensitiveServiceExposure(), // A.8.21
            $this->checkIpForwardHygiene(),       // A.8.22
            $this->checkEtcUnderVersionControl(), // A.8.32
            $this->checkPendingSecurityUpdates(), // A.5.31
            $this->checkSshKeyFilePermissions(),  // A.8.5
            $this->checkTlsCertExpiry(),          // A.8.24
            $this->checkSuidBinariesCensus(),     // A.8.9
            $this->checkRootHistorySanitation(),  // A.5.16
            $this->checkStorageRedundancy(),      // A.8.14
            $this->checkHomeDirPermissions(),     // A.8.3
        ];

        return $this->summarize($checks);
    }

    /* ------------------------------------------------------------------ */
    /* Individual checks                                                   */
    /* ------------------------------------------------------------------ */

    /** A.5.15 / A.8.2 — 僅 root 擁有 UID 0。 */
    private function checkRootAccounts(): array
    {
        $passwd = @file_get_contents('/etc/passwd');
        if ($passwd === false) {
            return $this->na('A.5.15', '存取控制', '無法讀取 /etc/passwd');
        }

        $uidZero = [];
        foreach (explode("\n", $passwd) as $line) {
            $parts = explode(':', $line);
            if (count($parts) >= 3 && $parts[2] === '0') {
                $uidZero[] = $parts[0];
            }
        }

        $extra = array_values(array_diff($uidZero, ['root']));
        if (empty($extra)) {
            return $this->pass(
                'A.5.15', '存取控制', self::SEV_CRITICAL,
                '僅 root 擁有 UID 0。',
                '找到 UID 0 帳號：' . implode(', ', $uidZero),
            );
        }

        return $this->fail(
            'A.5.15', '存取控制', self::SEV_CRITICAL,
            '存在非 root 的 UID 0 帳號，等同於隱藏的超級使用者。',
            'UID 0 帳號：' . implode(', ', $uidZero),
            '移除多餘的 UID 0 帳號，或改以 sudo 授權。',
        );
    }

    /** A.5.17 — /etc/login.defs 密碼策略。 */
    private function checkPasswordPolicy(): array
    {
        $file = '/etc/login.defs';
        if (!is_readable($file)) {
            return $this->na('A.5.17', '身分驗證資訊', '/etc/login.defs 不存在或無法讀取（非 Linux 主機常見）。');
        }

        $content = (string) @file_get_contents($file);
        $max = $this->matchInt($content, '/^\s*PASS_MAX_DAYS\s+(\d+)/m');
        $min = $this->matchInt($content, '/^\s*PASS_MIN_LEN\s+(\d+)/m');
        $warn = $this->matchInt($content, '/^\s*PASS_WARN_AGE\s+(\d+)/m');

        $issues = [];
        if ($max === null || $max > 90) {
            $issues[] = 'PASS_MAX_DAYS=' . ($max ?? '未設定') . '（建議 ≤ 90）';
        }
        if ($min === null || $min < 12) {
            $issues[] = 'PASS_MIN_LEN=' . ($min ?? '未設定') . '（建議 ≥ 12）';
        }
        if ($warn === null || $warn < 7) {
            $issues[] = 'PASS_WARN_AGE=' . ($warn ?? '未設定') . '（建議 ≥ 7）';
        }

        $evidence = sprintf('PASS_MAX_DAYS=%s, PASS_MIN_LEN=%s, PASS_WARN_AGE=%s', $max ?? '-', $min ?? '-', $warn ?? '-');

        if (empty($issues)) {
            return $this->pass('A.5.17', '身分驗證資訊', self::SEV_MEDIUM, '密碼策略符合基準。', $evidence);
        }

        return $this->warn(
            'A.5.17', '身分驗證資訊', self::SEV_MEDIUM,
            '密碼策略較弱。', $evidence,
            '在 /etc/login.defs 設定 PASS_MAX_DAYS≤90、PASS_MIN_LEN≥12、PASS_WARN_AGE≥7。',
        );
    }

    /** A.8.2 — sudoers 中不應有無密碼提權。 */
    private function checkSudoersNoPasswd(): array
    {
        $out = [];
        $files = ['/etc/sudoers'];
        foreach (@glob('/etc/sudoers.d/*') ?: [] as $f) {
            $files[] = $f;
        }

        $offenders = [];
        foreach ($files as $f) {
            $content = @file_get_contents($f);
            if ($content === false) {
                continue;
            }
            foreach (explode("\n", $content) as $line) {
                $trim = trim($line);
                if ($trim === '' || str_starts_with($trim, '#')) {
                    continue;
                }
                if (preg_match('/NOPASSWD\s*:/i', $trim)) {
                    $offenders[] = basename($f) . ': ' . $trim;
                }
            }
        }

        if (empty($offenders)) {
            return $this->pass('A.8.2', '特權存取權限', self::SEV_HIGH, 'sudoers 未使用 NOPASSWD。');
        }

        return $this->warn(
            'A.8.2', '特權存取權限', self::SEV_HIGH,
            'sudoers 設定了 NOPASSWD，等同於免密碼提權。',
            implode("\n", array_slice($offenders, 0, 5)) . (count($offenders) > 5 ? "\n…（已截斷）" : ''),
            '審查 NOPASSWD 條目，改為需密碼或限制特定指令。',
        );
    }

    /** A.8.3 — /etc/shadow 權限不應對非 root 可讀。 */
    private function checkShadowPermissions(): array
    {
        $file = '/etc/shadow';
        if (!file_exists($file)) {
            return $this->na('A.8.3', '資訊存取限制', '/etc/shadow 不存在（非 Linux 主機常見）。');
        }

        $perms = @fileperms($file);
        if ($perms === false) {
            return $this->na('A.8.3', '資訊存取限制', '無法讀取 /etc/shadow 權限（可能無足夠 privilege）。');
        }

        $mode = $perms & 0777;
        $modeStr = sprintf('%04o', $mode);
        $worldOrGroupReadable = ($mode & 0044) !== 0;

        if (!$worldOrGroupReadable) {
            return $this->pass('A.8.3', '資訊存取限制', self::SEV_CRITICAL,
                '/etc/shadow 權限正確。', "mode=$modeStr");
        }

        return $this->fail(
            'A.8.3', '資訊存取限制', self::SEV_CRITICAL,
            '/etc/shadow 可被 group 或 world 讀取，密碼雜湊可能外洩。',
            "mode=$modeStr",
            'chown root:shadow /etc/shadow && chmod 640 /etc/shadow',
        );
    }

    /** A.8.5 — SSH 安全基準。 */
    private function checkSshConfig(): array
    {
        $file = '/etc/ssh/sshd_config';
        if (!is_readable($file)) {
            return $this->na('A.8.5', '安全驗證', 'sshd_config 不存在或無法讀取。');
        }

        $content = (string) @file_get_contents($file);
        $permitRoot = $this->matchStr($content, '/^\s*PermitRootLogin\s+(\S+)/mi');
        $passwordAuth = $this->matchStr($content, '/^\s*PasswordAuthentication\s+(\S+)/mi');
        $protocol = $this->matchStr($content, '/^\s*Protocol\s+(\S+)/mi');
        $x11 = $this->matchStr($content, '/^\s*X11Forwarding\s+(\S+)/mi');

        $issues = [];
        if ($permitRoot !== null && !in_array(strtolower($permitRoot), ['no', 'prohibit-password'], true)) {
            $issues[] = "PermitRootLogin={$permitRoot}（建議 no）";
        }
        if ($passwordAuth !== null && strtolower($passwordAuth) !== 'no') {
            $issues[] = "PasswordAuthentication={$passwordAuth}（建議 no，改用金鑰登入）";
        }
        if ($protocol !== null && $protocol !== '2') {
            $issues[] = "Protocol={$protocol}（僅允許 2）";
        }
        if ($x11 !== null && strtolower($x11) === 'yes') {
            $issues[] = 'X11Forwarding=yes（若非必要建議關閉）';
        }

        $evidence = sprintf(
            'PermitRootLogin=%s, PasswordAuthentication=%s, Protocol=%s, X11Forwarding=%s',
            $permitRoot ?? '(default)', $passwordAuth ?? '(default)', $protocol ?? '(default)', $x11 ?? '(default)',
        );

        if (empty($issues)) {
            return $this->pass('A.8.5', '安全驗證', self::SEV_HIGH, 'SSH 設定符合基準。', $evidence);
        }

        return $this->warn(
            'A.8.5', '安全驗證', self::SEV_HIGH,
            'SSH 設定偏離安全基準：' . implode('；', $issues),
            $evidence,
            '編輯 /etc/ssh/sshd_config 修正上述項目並重啟 sshd。',
        );
    }

    /** A.8.7 — 惡意軟體防護（ClamAV）。 */
    private function checkMalwareProtection(): array
    {
        $clamscan = $this->which('clamscan');
        $freshclam = $this->which('freshclam');
        if ($clamscan === null) {
            return $this->fail('A.8.7', '對抗惡意軟體', self::SEV_HIGH,
                '系統未安裝 ClamAV。', 'clamscan not found in PATH',
                '安裝 ClamAV：apt install clamav clamav-daemon 或等效套件。');
        }

        $reportFile = storage_path('app/clamav_report.json');
        $ageDays = null;
        if (is_readable($reportFile)) {
            $ageDays = (int) floor((time() - filemtime($reportFile)) / 86400);
        }

        $evidence = "clamscan=$clamscan" . ($freshclam ? ", freshclam=$freshclam" : '');
        if ($ageDays === null) {
            return $this->warn('A.8.7', '對抗惡意軟體', self::SEV_MEDIUM,
                'ClamAV 已安裝但尚未看到最近的掃描紀錄。', $evidence,
                '執行 artisan ids:scan 或確認排程掃描已啟用。');
        }

        if ($ageDays > 7) {
            return $this->warn('A.8.7', '對抗惡意軟體', self::SEV_MEDIUM,
                '最近一次 ClamAV 掃描已超過 7 天。', "最後掃描：{$ageDays} 天前",
                '提高掃描頻率（至少每週一次）。');
        }

        return $this->pass('A.8.7', '對抗惡意軟體', self::SEV_HIGH,
            'ClamAV 已安裝且近期有掃描紀錄。',
            "{$evidence}；最後掃描：{$ageDays} 天前");
    }

    /** A.8.8 — 自動安全更新。 */
    private function checkUnattendedUpgrades(): array
    {
        if (file_exists('/etc/apt/apt.conf.d/50unattended-upgrades')) {
            $periodic = @file_get_contents('/etc/apt/apt.conf.d/20auto-upgrades');
            $enabled = $periodic !== false && preg_match('/Unattended-Upgrade\s*"1"/', $periodic);
            if ($enabled) {
                return $this->pass('A.8.8', '技術弱點管理', self::SEV_HIGH,
                    'unattended-upgrades 已啟用。',
                    '/etc/apt/apt.conf.d/20auto-upgrades 設定為 1。');
            }
            return $this->warn('A.8.8', '技術弱點管理', self::SEV_HIGH,
                'unattended-upgrades 已安裝但未啟用。',
                '/etc/apt/apt.conf.d/20auto-upgrades 未正確啟用。',
                'dpkg-reconfigure -plow unattended-upgrades');
        }

        if (file_exists('/etc/dnf/automatic.conf') || file_exists('/etc/yum/yum-cron.conf')) {
            return $this->pass('A.8.8', '技術弱點管理', self::SEV_HIGH,
                '偵測到 dnf-automatic / yum-cron 設定。');
        }

        return $this->warn('A.8.8', '技術弱點管理', self::SEV_HIGH,
            '未偵測到自動安全更新機制。', '未找到 unattended-upgrades / dnf-automatic / yum-cron。',
            '安裝 unattended-upgrades（Debian/Ubuntu）或 dnf-automatic（RHEL 家族）。');
    }

    /** A.8.9 — 檔案完整性。 */
    private function checkFileIntegrity(): array
    {
        foreach (['aide', 'tripwire', 'samhain'] as $tool) {
            if ($this->which($tool) !== null) {
                return $this->pass('A.8.9', '配置管理', self::SEV_MEDIUM,
                    "偵測到檔案完整性工具：{$tool}。", "which {$tool} → " . $this->which($tool));
            }
        }
        return $this->warn('A.8.9', '配置管理', self::SEV_MEDIUM,
            '未偵測到檔案完整性監控工具（aide/tripwire/samhain）。',
            '上述三個工具均未找到。',
            '安裝 aide 並定期比對基線：apt install aide && aideinit。');
    }

    /** A.8.15 — 系統記錄檔。 */
    private function checkLogging(): array
    {
        $rsyslog = $this->isServiceActive('rsyslog') || $this->isServiceActive('systemd-journald');
        $auditd = $this->isServiceActive('auditd');
        $logrotate = file_exists('/etc/logrotate.conf') || is_dir('/etc/logrotate.d');

        $evidence = sprintf('rsyslog/journald=%s, auditd=%s, logrotate=%s',
            $rsyslog ? 'active' : 'inactive',
            $auditd ? 'active' : 'inactive',
            $logrotate ? 'present' : 'missing');

        if ($rsyslog && $logrotate) {
            return $this->pass('A.8.15', '記錄檔', self::SEV_HIGH,
                '系統記錄服務運作中且 logrotate 已設定。', $evidence);
        }

        return $this->warn('A.8.15', '記錄檔', self::SEV_HIGH,
            '系統記錄服務或輪替設定不完整。', $evidence,
            '確保 rsyslog/systemd-journald 運作且設定 logrotate 輪替原則。');
    }

    /** A.8.16 — 入侵偵測/防禦。 */
    private function checkIdsIps(): array
    {
        $suricata = $this->isServiceActive('suricata') || $this->pgrep('suricata');
        $snort = $this->isServiceActive('snort') || $this->pgrep('snort');
        $fail2ban = $this->isServiceActive('fail2ban');

        $evidence = sprintf('suricata=%s, snort=%s, fail2ban=%s',
            $suricata ? 'active' : 'inactive',
            $snort ? 'active' : 'inactive',
            $fail2ban ? 'active' : 'inactive');

        if ($suricata || $snort) {
            return $this->pass('A.8.16', '監控活動', self::SEV_HIGH,
                '已偵測到活動中的 IDS/IPS 引擎。', $evidence);
        }

        return $this->fail('A.8.16', '監控活動', self::SEV_HIGH,
            '未偵測到運作中的 IDS/IPS（Suricata/Snort）。', $evidence,
            '透過 artisan ids:sync-suricata 啟用 Suricata，或安裝 Snort。');
    }

    /** A.8.17 — 時鐘同步。 */
    private function checkTimeSync(): array
    {
        foreach (['chrony', 'chronyd', 'ntpd', 'ntp', 'systemd-timesyncd'] as $svc) {
            if ($this->isServiceActive($svc)) {
                return $this->pass('A.8.17', '時鐘同步', self::SEV_MEDIUM,
                    "時間同步服務運作中：{$svc}。");
            }
        }

        if (PHP_OS_FAMILY === 'Darwin') {
            $out = $this->runCmd(['systemsetup', '-getusingnetworktime']);
            if ($out !== null && str_contains(strtolower($out), 'on')) {
                return $this->pass('A.8.17', '時鐘同步', self::SEV_MEDIUM, 'macOS 網路時間已啟用。', trim($out));
            }
        }

        return $this->warn('A.8.17', '時鐘同步', self::SEV_MEDIUM,
            '未偵測到時鐘同步服務。',
            '檢查 chrony / ntpd / systemd-timesyncd 皆未啟用。',
            '啟用 systemd-timesyncd：timedatectl set-ntp true。');
    }

    /** A.8.20 — 網路安全（防火牆）。 */
    private function checkFirewall(): array
    {
        if ($this->which('ufw')) {
            $out = $this->runCmd(['ufw', 'status']);
            if ($out !== null && str_contains(strtolower($out), 'status: active')) {
                return $this->pass('A.8.20', '網路安全', self::SEV_HIGH, 'ufw 啟用中。', trim(explode("\n", $out)[0] ?? ''));
            }
        }
        if ($this->which('firewall-cmd')) {
            $out = $this->runCmd(['firewall-cmd', '--state']);
            if ($out !== null && trim($out) === 'running') {
                return $this->pass('A.8.20', '網路安全', self::SEV_HIGH, 'firewalld 啟用中。');
            }
        }
        if ($this->which('nft')) {
            $out = $this->runCmd(['nft', 'list', 'ruleset']);
            if ($out !== null && trim($out) !== '') {
                return $this->pass('A.8.20', '網路安全', self::SEV_HIGH, 'nftables 已設定規則。');
            }
        }
        if ($this->which('iptables')) {
            $out = $this->runCmd(['iptables', '-S']);
            if ($out !== null && substr_count($out, "\n") > 3) {
                return $this->pass('A.8.20', '網路安全', self::SEV_HIGH, 'iptables 已設定規則。');
            }
        }

        return $this->fail('A.8.20', '網路安全', self::SEV_CRITICAL,
            '未偵測到啟用中的主機防火牆。', '檢查 ufw/firewalld/nftables/iptables 皆無有效規則。',
            '啟用主機防火牆：ufw enable 或 systemctl enable --now firewalld。');
    }

    /** A.8.24 — 磁碟加密。 */
    private function checkDiskEncryption(): array
    {
        $out = $this->runCmd(['lsblk', '-o', 'NAME,TYPE']);
        if ($out !== null && preg_match('/\bcrypt\b/', $out)) {
            return $this->pass('A.8.24', '使用密碼術', self::SEV_MEDIUM,
                '偵測到加密區塊裝置（LUKS）。', '在 lsblk 輸出中找到 type=crypt。');
        }

        if (PHP_OS_FAMILY === 'Darwin') {
            $out = $this->runCmd(['fdesetup', 'status']);
            if ($out !== null && str_contains(strtolower($out), 'filevault is on')) {
                return $this->pass('A.8.24', '使用密碼術', self::SEV_MEDIUM, 'FileVault 已啟用。', trim($out));
            }
        }

        return $this->warn('A.8.24', '使用密碼術', self::SEV_MEDIUM,
            '未偵測到全磁碟加密。', '未找到 LUKS / FileVault 跡證。',
            '針對儲存敏感資料的磁碟啟用 LUKS 或 FileVault。');
    }

    /** A.8.24 — SSH 密碼學強度。 */
    private function checkSshCiphers(): array
    {
        $file = '/etc/ssh/sshd_config';
        if (!is_readable($file)) {
            return $this->na('A.8.24-ssh', '使用密碼術（SSH）', 'sshd_config 無法讀取。');
        }

        $content = (string) @file_get_contents($file);
        $ciphers = $this->matchStr($content, '/^\s*Ciphers\s+(.+)$/mi');
        $macs = $this->matchStr($content, '/^\s*MACs\s+(.+)$/mi');
        $kex = $this->matchStr($content, '/^\s*KexAlgorithms\s+(.+)$/mi');

        $weak = [];
        $weakPatterns = ['3des-cbc', 'aes128-cbc', 'aes256-cbc', 'arcfour', 'blowfish', 'rc4', 'hmac-md5', 'hmac-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'];
        foreach ([$ciphers, $macs, $kex] as $line) {
            if (!$line) {
                continue;
            }
            foreach ($weakPatterns as $p) {
                if (stripos($line, $p) !== false) {
                    $weak[] = $p;
                }
            }
        }

        $evidence = 'Ciphers=' . ($ciphers ?? '(default)') . "\nMACs=" . ($macs ?? '(default)') . "\nKexAlgorithms=" . ($kex ?? '(default)');

        if (empty($weak)) {
            return $this->pass('A.8.24-ssh', '使用密碼術（SSH）', self::SEV_MEDIUM,
                'SSH 未啟用已知弱密碼組合。', $evidence);
        }

        return $this->warn('A.8.24-ssh', '使用密碼術（SSH）', self::SEV_MEDIUM,
            'SSH 設定包含已知弱演算法：' . implode(', ', array_unique($weak)),
            $evidence,
            '在 sshd_config 僅允許 chacha20/aes-gcm/aes-ctr 與 hmac-sha2 / curve25519 等強演算法。');
    }

    /** A.8.13 — 備份。 */
    private function checkBackupEvidence(): array
    {
        $hits = [];
        foreach (['borg', 'restic', 'rsnapshot', 'duplicity', 'bacula-fd'] as $tool) {
            if ($this->which($tool) !== null) {
                $hits[] = $tool;
            }
        }
        foreach (['/etc/cron.d', '/etc/cron.daily'] as $dir) {
            foreach (@glob($dir . '/*backup*') ?: [] as $f) {
                $hits[] = $f;
            }
        }

        if (!empty($hits)) {
            return $this->pass('A.8.13', '資訊備份', self::SEV_MEDIUM,
                '偵測到備份工具或備份排程。', implode(', ', array_unique($hits)));
        }

        return $this->warn('A.8.13', '資訊備份', self::SEV_MEDIUM,
            '未偵測到備份工具或排程。', '檢查常見備份工具與 /etc/cron.* 皆無 *backup* 條目。',
            '建立定期備份機制（例：borg/restic + cron/systemd-timer）並測試還原。');
    }

    /* ================================================================== */
    /* Extended rule set                                                   */
    /* ================================================================== */

    /** A.5.7 — 威脅情報：fail2ban。 */
    private function checkFail2ban(): array
    {
        if ($this->which('fail2ban-client') === null) {
            return $this->warn('A.5.7', '威脅情報', self::SEV_MEDIUM,
                '未安裝 fail2ban（可自動封鎖暴力破解來源）。',
                'fail2ban-client not found in PATH',
                '安裝：apt install fail2ban 並啟用 sshd jail。');
        }
        if (!$this->isServiceActive('fail2ban')) {
            return $this->warn('A.5.7', '威脅情報', self::SEV_MEDIUM,
                'fail2ban 已安裝但未啟動。', 'systemctl is-active fail2ban ≠ active',
                'systemctl enable --now fail2ban');
        }
        $out = $this->runCmd(['fail2ban-client', 'status']);
        $jails = ($out !== null && preg_match('/Number of jail:\s*(\d+)/', $out, $m)) ? (int) $m[1] : 0;
        if ($jails === 0) {
            return $this->warn('A.5.7', '威脅情報', self::SEV_MEDIUM,
                'fail2ban 運作中但沒有啟用任何 jail。', trim($out ?? ''),
                '啟用 sshd jail：enabled = true 於 /etc/fail2ban/jail.local。');
        }
        return $this->pass('A.5.7', '威脅情報', self::SEV_MEDIUM,
            "fail2ban 啟用中，共 {$jails} 個 jail。", trim($out ?? ''));
    }

    /** A.8.1 — 使用者終端：閒置登出。 */
    private function checkIdleSessionTimeout(): array
    {
        $sources = ['/etc/profile', '/etc/bash.bashrc', '/etc/profile.d/tmout.sh'];
        foreach (@glob('/etc/profile.d/*.sh') ?: [] as $p) {
            $sources[] = $p;
        }
        foreach (array_unique($sources) as $f) {
            if (!is_readable($f)) {
                continue;
            }
            $content = (string) @file_get_contents($f);
            if (preg_match('/^\s*(?:export\s+)?TMOUT=(\d+)/m', $content, $m) && (int) $m[1] > 0 && (int) $m[1] <= 900) {
                return $this->pass('A.8.1', '使用者終端設備', self::SEV_LOW,
                    "Shell 閒置登出 TMOUT={$m[1]} 秒（於 {$f}）。");
            }
        }
        return $this->warn('A.8.1', '使用者終端設備', self::SEV_LOW,
            '未設定 shell 閒置自動登出（TMOUT）。',
            '檢查 /etc/profile 與 /etc/profile.d/*.sh 皆無有效 TMOUT。',
            '於 /etc/profile.d/tmout.sh 加上 readonly TMOUT=600; export TMOUT。');
    }

    /** A.8.6 — 容量管理：磁碟使用率。 */
    private function checkDiskCapacity(): array
    {
        $out = $this->runCmd(['df', '-P', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'overlay', '-x', 'squashfs']);
        if ($out === null) {
            return $this->na('A.8.6', '容量管理（磁碟）', '無法執行 df。');
        }
        $issues = [];
        $lines = array_slice(preg_split('/\r?\n/', trim($out)), 1);
        foreach ($lines as $line) {
            if (!preg_match('/\s(\d+)%\s+(\/\S*)$/', $line, $m)) {
                continue;
            }
            $pct = (int) $m[1];
            $mount = $m[2];
            if ($pct >= 90) {
                $issues[] = "$mount 使用 {$pct}%";
            }
        }
        if (empty($issues)) {
            return $this->pass('A.8.6', '容量管理（磁碟）', self::SEV_MEDIUM,
                '所有掛載點使用率 < 90%。', trim($out));
        }
        return $this->warn('A.8.6', '容量管理（磁碟）', self::SEV_MEDIUM,
            '偵測到高使用率掛載點：' . implode('、', $issues),
            trim($out),
            '清理舊資料／擴充磁碟／加上監控告警。');
    }

    /** A.8.6 — 容量管理：inode。 */
    private function checkInodeCapacity(): array
    {
        $out = $this->runCmd(['df', '-iP', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'overlay', '-x', 'squashfs']);
        if ($out === null) {
            return $this->na('A.8.6', '容量管理（inode）', '無法執行 df -i。');
        }
        $issues = [];
        $lines = array_slice(preg_split('/\r?\n/', trim($out)), 1);
        foreach ($lines as $line) {
            if (!preg_match('/\s(\d+)%\s+(\/\S*)$/', $line, $m)) {
                continue;
            }
            if ((int) $m[1] >= 90) {
                $issues[] = $m[2] . " inode 使用 {$m[1]}%";
            }
        }
        if (empty($issues)) {
            return $this->pass('A.8.6', '容量管理（inode）', self::SEV_MEDIUM, '所有檔案系統 inode 使用率 < 90%。');
        }
        return $this->warn('A.8.6', '容量管理（inode）', self::SEV_MEDIUM,
            '偵測到 inode 耗盡風險：' . implode('、', $issues),
            trim($out),
            '清理含大量小檔案的路徑，或提高 inode 配額。');
    }

    /** A.8.21 — 網路服務安全：開放埠。 */
    private function checkListeningServices(): array
    {
        $out = $this->runCmd(['ss', '-tlnpH']) ?? $this->runCmd(['ss', '-tln']);
        if ($out === null) {
            return $this->na('A.8.21', '網路服務安全', '無法執行 ss。');
        }
        $public = [];
        foreach (preg_split('/\r?\n/', trim($out)) as $line) {
            if (preg_match('/\s(?:0\.0\.0\.0|\*|\[::\]):(\d+)\s/', $line, $m)) {
                $public[] = (int) $m[1];
            }
        }
        $public = array_values(array_unique($public));
        sort($public);
        $count = count($public);
        $evidence = '公開監聽埠：' . ($public ? implode(', ', $public) : '(無)');

        if ($count === 0) {
            return $this->pass('A.8.21', '網路服務安全', self::SEV_MEDIUM, '無對外監聽服務。');
        }
        if ($count > 10) {
            return $this->warn('A.8.21', '網路服務安全', self::SEV_MEDIUM,
                "對外監聽 {$count} 個 TCP 埠，建議檢視是否必要。", $evidence,
                '停用非必要服務，或改為只綁定 127.0.0.1。');
        }
        return $this->pass('A.8.21', '網路服務安全', self::SEV_MEDIUM,
            "對外監聽 {$count} 個 TCP 埠。", $evidence);
    }

    /** A.8.9 — 核心強化（sysctl）。 */
    private function checkKernelHardening(): array
    {
        $expected = [
            'kernel.randomize_va_space' => ['2'],
            'net.ipv4.tcp_syncookies' => ['1'],
            'kernel.kptr_restrict' => ['1', '2'],
            'kernel.yama.ptrace_scope' => ['1', '2', '3'],
            'net.ipv4.conf.all.rp_filter' => ['1', '2'],
        ];
        $missing = [];
        $evidenceLines = [];
        foreach ($expected as $key => $wants) {
            $out = $this->runCmd(['sysctl', '-n', $key]);
            $val = $out !== null ? trim($out) : null;
            $evidenceLines[] = "$key = " . ($val ?? 'n/a');
            if ($val === null || !in_array($val, $wants, true)) {
                $missing[] = "{$key}≠" . implode('|', $wants);
            }
        }
        if (empty($missing)) {
            return $this->pass('A.8.9-kernel', '核心強化', self::SEV_MEDIUM,
                '常見核心硬化參數均符合建議。', implode("\n", $evidenceLines));
        }
        return $this->warn('A.8.9-kernel', '核心強化', self::SEV_MEDIUM,
            '核心硬化參數不完整：' . implode('、', $missing),
            implode("\n", $evidenceLines),
            '於 /etc/sysctl.d/99-hardening.conf 加入上述建議值並 sysctl --system。');
    }

    /** A.8.9 — /tmp 掛載選項。 */
    private function checkTmpMountOptions(): array
    {
        $fstab = @file_get_contents('/etc/fstab');
        if ($fstab === false) {
            return $this->na('A.8.9-tmp', '/tmp 掛載', '無法讀取 /etc/fstab。');
        }
        $mountOut = $this->runCmd(['mount']);
        $tmpLine = null;
        if ($mountOut !== null) {
            foreach (preg_split('/\r?\n/', $mountOut) as $line) {
                if (preg_match('/\son\s+\/tmp\s/', $line)) {
                    $tmpLine = $line;
                    break;
                }
            }
        }
        if ($tmpLine === null) {
            return $this->warn('A.8.9-tmp', '/tmp 掛載', self::SEV_LOW,
                '/tmp 未獨立掛載，nosuid/noexec 無法套用。',
                '於 mount 輸出找不到 /tmp 的獨立項目。',
                '將 /tmp 改為獨立分割或 tmpfs，並加上 nosuid,noexec,nodev。');
        }
        $flags = [];
        foreach (['nosuid', 'noexec', 'nodev'] as $f) {
            if (strpos($tmpLine, $f) === false) {
                $flags[] = $f;
            }
        }
        if (empty($flags)) {
            return $this->pass('A.8.9-tmp', '/tmp 掛載', self::SEV_LOW,
                '/tmp 已加上 nosuid,noexec,nodev。', trim($tmpLine));
        }
        return $this->warn('A.8.9-tmp', '/tmp 掛載', self::SEV_LOW,
            '/tmp 缺少安全掛載選項：' . implode(', ', $flags),
            trim($tmpLine),
            '於 /etc/fstab 該列補上 nosuid,noexec,nodev 並重新掛載。');
    }

    /** A.5.16 — 空密碼帳號。 */
    private function checkEmptyPasswords(): array
    {
        $shadow = @file_get_contents('/etc/shadow');
        if ($shadow === false) {
            return $this->na('A.5.16', '身分管理', '無法讀取 /etc/shadow（權限不足）。');
        }
        $offenders = [];
        foreach (preg_split('/\r?\n/', $shadow) as $line) {
            $parts = explode(':', $line);
            if (count($parts) >= 2 && $parts[1] === '') {
                $offenders[] = $parts[0];
            }
        }
        if (empty($offenders)) {
            return $this->pass('A.5.16', '身分管理（空密碼）', self::SEV_CRITICAL, '沒有帳號使用空密碼。');
        }
        return $this->fail('A.5.16', '身分管理（空密碼）', self::SEV_CRITICAL,
            '發現空密碼帳號：' . implode(', ', $offenders),
            '/etc/shadow 欄位 2 為空的帳號：' . implode(', ', $offenders),
            'passwd -l <user> 鎖定，或指派強密碼。');
    }

    /** A.8.3 — /etc 中的 world-writable 檔案。 */
    private function checkWorldWritableCriticalFiles(): array
    {
        $out = $this->runCmd(['find', '/etc', '-xdev', '-type', 'f', '-perm', '-0002'], 10);
        if ($out === null) {
            return $this->na('A.8.3-ww', 'world-writable 檔案', '無法執行 find。');
        }
        $lines = array_filter(preg_split('/\r?\n/', trim($out)));
        if (empty($lines)) {
            return $this->pass('A.8.3-ww', 'world-writable 檔案', self::SEV_HIGH, '/etc 下沒有任何 world-writable 檔案。');
        }
        return $this->fail('A.8.3-ww', 'world-writable 檔案', self::SEV_HIGH,
            '/etc 下存在可被任何使用者改寫的檔案，可能被用於提權。',
            implode("\n", array_slice($lines, 0, 20)) . (count($lines) > 20 ? "\n…（共 " . count($lines) . ' 筆，已截斷）' : ''),
            'chmod o-w <檔案> 移除 world-writable。');
    }

    /** A.8.5 — 存在管理員金鑰，搭配密碼驗證停用。 */
    private function checkSshKeyAuthPresence(): array
    {
        $hits = [];
        foreach (['/root/.ssh/authorized_keys'] as $f) {
            if (is_file($f) && filesize($f) > 0) {
                $hits[] = basename(dirname(dirname($f))) . '/.ssh/authorized_keys (' . filesize($f) . ' bytes)';
            }
        }
        foreach (@glob('/home/*/.ssh/authorized_keys') ?: [] as $f) {
            if (is_file($f) && filesize($f) > 0) {
                $hits[] = basename(dirname(dirname($f))) . '/.ssh/authorized_keys (' . filesize($f) . ' bytes)';
            }
        }
        if (empty($hits)) {
            return $this->warn('A.8.5-key', 'SSH 金鑰登入', self::SEV_MEDIUM,
                '未偵測到任何 SSH 金鑰檔，可能完全仰賴密碼登入。',
                '/root/.ssh/authorized_keys 與 /home/*/.ssh/authorized_keys 皆不存在或為空。',
                '建立金鑰登入後停用 PasswordAuthentication。');
        }
        return $this->pass('A.8.5-key', 'SSH 金鑰登入', self::SEV_MEDIUM,
            '已偵測到 SSH 授權金鑰檔。', implode("\n", $hits));
    }

    /** A.8.18 — cron 衛生。 */
    private function checkCronHygiene(): array
    {
        $bad = [];
        foreach (['/etc/cron.d'] as $d) {
            if (!is_dir($d)) {
                continue;
            }
            foreach (@glob($d . '/*') ?: [] as $f) {
                if (!is_file($f)) {
                    continue;
                }
                $perms = @fileperms($f) & 0777;
                if (($perms & 0022) !== 0) {
                    $bad[] = $f . ' mode=' . sprintf('%04o', $perms);
                }
                $content = (string) @file_get_contents($f);
                if (preg_match('/curl[^|\n]*\|\s*(?:bash|sh)/', $content)) {
                    $bad[] = $f . ' → 可疑 curl-to-shell 指令';
                }
            }
        }
        if (empty($bad)) {
            return $this->pass('A.8.18', '特權公用程式（cron）', self::SEV_MEDIUM,
                '/etc/cron.d 無可寫或可疑條目。');
        }
        return $this->warn('A.8.18', '特權公用程式（cron）', self::SEV_MEDIUM,
            'cron 設定存在風險：' . count($bad) . ' 項。',
            implode("\n", array_slice($bad, 0, 10)),
            '將 /etc/cron.d/* 權限設為 0644 或更嚴格，檢視 curl|bash 類指令。');
    }

    /** A.8.19 — apt 來源是否帶簽章。 */
    private function checkUnsignedAptSources(): array
    {
        $sources = [];
        if (is_file('/etc/apt/sources.list')) {
            $sources[] = '/etc/apt/sources.list';
        }
        foreach (@glob('/etc/apt/sources.list.d/*.list') ?: [] as $f) {
            $sources[] = $f;
        }
        foreach (@glob('/etc/apt/sources.list.d/*.sources') ?: [] as $f) {
            $sources[] = $f;
        }
        if (empty($sources)) {
            return $this->na('A.8.19', '軟體安裝', '不是 Debian/Ubuntu 家族或找不到 apt sources。');
        }
        $unsigned = [];
        foreach ($sources as $f) {
            $content = (string) @file_get_contents($f);
            foreach (preg_split('/\r?\n/', $content) as $line) {
                $trim = trim($line);
                if ($trim === '' || str_starts_with($trim, '#')) {
                    continue;
                }
                if (preg_match('/^\s*deb\s+\[([^\]]*)\]/', $trim, $m)) {
                    if (stripos($m[1], 'signed-by') === false && stripos($m[1], 'trusted') !== false) {
                        $unsigned[] = basename($f) . ': ' . $trim;
                    }
                } elseif (preg_match('/^\s*deb\s+http/', $trim)) {
                    // Legacy "deb http..." without options: relies on keyring trust.gpg.d.
                    // Acceptable if at least one signed-by keyring exists; otherwise flag.
                    if (empty(@glob('/etc/apt/trusted.gpg.d/*.gpg'))) {
                        $unsigned[] = basename($f) . ': ' . $trim;
                    }
                }
            }
        }
        if (empty($unsigned)) {
            return $this->pass('A.8.19', '軟體安裝', self::SEV_MEDIUM,
                'apt 來源皆具備 GPG 簽章驗證。', '檢視 ' . count($sources) . ' 個 apt 設定檔。');
        }
        return $this->warn('A.8.19', '軟體安裝', self::SEV_MEDIUM,
            '存在未簽章（或以 trusted=yes 取巧）的 apt 來源。',
            implode("\n", array_slice($unsigned, 0, 5)) . (count($unsigned) > 5 ? "\n…（已截斷）" : ''),
            '於 deb 行加上 [signed-by=/etc/apt/keyrings/xxx.gpg] 並移除 trusted=yes。');
    }

    /** A.5.16 — 沉睡帳號。 */
    private function checkDormantAccounts(): array
    {
        if ($this->which('lastlog') === null) {
            return $this->na('A.5.16-dormant', '身分管理（沉睡帳號）', 'lastlog 不存在。');
        }
        $out = $this->runCmd(['lastlog']);
        if ($out === null) {
            return $this->na('A.5.16-dormant', '身分管理（沉睡帳號）', '無法執行 lastlog。');
        }
        $dormant = [];
        foreach (preg_split('/\r?\n/', $out) as $line) {
            if (preg_match('/^(\S+)\s+.*\*\*Never logged in\*\*/', $line, $m)) {
                $user = $m[1];
                if (in_array($user, ['root', 'Username'], true)) {
                    continue;
                }
                // Skip system accounts with shell = nologin/false.
                $shell = $this->runCmd(['getent', 'passwd', $user]);
                if ($shell !== null && preg_match('/:(\/usr\/sbin\/nologin|\/bin\/false)\s*$/', $shell)) {
                    continue;
                }
                $dormant[] = $user;
            }
        }
        if (empty($dormant)) {
            return $this->pass('A.5.16-dormant', '身分管理（沉睡帳號）', self::SEV_LOW,
                '所有可登入帳號皆至少登入過一次。');
        }
        return $this->warn('A.5.16-dormant', '身分管理（沉睡帳號）', self::SEV_LOW,
            '存在從未登入過但可登入的帳號：' . implode(', ', $dormant),
            '依 lastlog 輸出判斷。',
            '確認需求後 passwd -l 鎖定或 userdel。');
    }

    /** A.8.9 — 核心傾印停用。 */
    private function checkCoreDumpDisabled(): array
    {
        $limitsOk = false;
        foreach (array_merge(['/etc/security/limits.conf'], @glob('/etc/security/limits.d/*') ?: []) as $f) {
            if (!is_readable($f)) {
                continue;
            }
            $c = (string) @file_get_contents($f);
            if (preg_match('/^\s*\*\s+(?:hard|soft)\s+core\s+0/m', $c)) {
                $limitsOk = true;
                break;
            }
        }
        $sysctl = $this->runCmd(['sysctl', '-n', 'fs.suid_dumpable']);
        $suidOk = $sysctl !== null && trim($sysctl) === '0';
        if ($limitsOk && $suidOk) {
            return $this->pass('A.8.9-core', '核心傾印', self::SEV_LOW,
                'core dump 已停用且 suid 程式禁止傾印。',
                "limits.conf OK；fs.suid_dumpable=" . trim($sysctl ?? '?'));
        }
        $issues = [];
        if (!$limitsOk) {
            $issues[] = '/etc/security/limits.* 未設定 hard core 0';
        }
        if (!$suidOk) {
            $issues[] = 'fs.suid_dumpable=' . trim($sysctl ?? 'unknown');
        }
        return $this->warn('A.8.9-core', '核心傾印', self::SEV_LOW,
            '核心傾印未完全停用。', implode('；', $issues),
            '於 /etc/security/limits.conf 加 "* hard core 0"，並設定 fs.suid_dumpable=0。');
    }

    /** A.8.24 — nginx/apache TLS 協定版本。 */
    private function checkWebServerTlsProtocol(): array
    {
        $files = array_merge(
            @glob('/etc/nginx/nginx.conf') ?: [],
            @glob('/etc/nginx/conf.d/*.conf') ?: [],
            @glob('/etc/nginx/sites-enabled/*') ?: [],
            @glob('/etc/apache2/apache2.conf') ?: [],
            @glob('/etc/apache2/sites-enabled/*') ?: [],
            @glob('/etc/httpd/conf.d/*.conf') ?: [],
        );
        $files = array_values(array_filter($files, 'is_file'));
        if (empty($files)) {
            return $this->na('A.8.24-web', 'Web 服務 TLS', '未偵測到 nginx/apache 設定。');
        }
        $weakHits = [];
        $sawTlsDirective = false;
        foreach ($files as $f) {
            $c = (string) @file_get_contents($f);
            if ($c === '') {
                continue;
            }
            if (preg_match_all('/ssl_protocols\s+([^;]+);/i', $c, $m1)) {
                $sawTlsDirective = true;
                foreach ($m1[1] as $proto) {
                    foreach (['SSLv2', 'SSLv3', 'TLSv1 ', 'TLSv1.0', 'TLSv1.1'] as $weak) {
                        if (stripos($proto, trim($weak)) !== false) {
                            $weakHits[] = basename($f) . ": {$proto}";
                        }
                    }
                }
            }
            if (preg_match_all('/SSLProtocol\s+([^\n]+)/i', $c, $m2)) {
                $sawTlsDirective = true;
                foreach ($m2[1] as $proto) {
                    foreach (['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'] as $weak) {
                        if (stripos($proto, $weak) !== false && strpos($proto, '-' . $weak) === false) {
                            $weakHits[] = basename($f) . ": {$proto}";
                        }
                    }
                }
            }
        }
        if (!$sawTlsDirective) {
            return $this->warn('A.8.24-web', 'Web 服務 TLS', self::SEV_MEDIUM,
                'nginx/apache 未明確設定 ssl_protocols / SSLProtocol，會沿用發行版預設。',
                '檢視 ' . count($files) . ' 個設定檔。',
                '明確設定 ssl_protocols TLSv1.2 TLSv1.3;（nginx）或 SSLProtocol -all +TLSv1.2 +TLSv1.3（apache）。');
        }
        if (empty($weakHits)) {
            return $this->pass('A.8.24-web', 'Web 服務 TLS', self::SEV_MEDIUM,
                'Web 服務未啟用已知的弱 TLS 協定版本。');
        }
        return $this->warn('A.8.24-web', 'Web 服務 TLS', self::SEV_MEDIUM,
            'Web 服務啟用了過時的 TLS 協定版本。',
            implode("\n", array_slice($weakHits, 0, 5)),
            '僅允許 TLSv1.2 與 TLSv1.3，停用其餘版本。');
    }

    /* ================================================================== */
    /* Third wave — auditd / deletion / exposure / certs / perms           */
    /* ================================================================== */

    /** A.5.28 — 證據收集：auditd 規則。 */
    private function checkAuditdRules(): array
    {
        if ($this->which('auditctl') === null) {
            return $this->warn('A.5.28', '證據收集', self::SEV_MEDIUM,
                '未安裝 auditd，無系統呼叫等級的稽核紀錄。',
                'auditctl 不存在。',
                '安裝：apt install auditd audispd-plugins 並啟用。');
        }
        if (!$this->isServiceActive('auditd')) {
            return $this->warn('A.5.28', '證據收集', self::SEV_MEDIUM,
                'auditd 已安裝但未啟動。', 'systemctl is-active auditd ≠ active',
                'systemctl enable --now auditd');
        }
        $out = $this->runCmd(['auditctl', '-l']);
        $ruleCount = 0;
        if ($out !== null) {
            $lines = preg_split('/\r?\n/', trim($out));
            foreach ($lines as $line) {
                if ($line === '' || str_starts_with(trim($line), 'No rules')) {
                    continue;
                }
                $ruleCount++;
            }
        }
        if ($ruleCount === 0) {
            return $this->warn('A.5.28', '證據收集', self::SEV_MEDIUM,
                'auditd 運作中但沒有載入任何規則，形同空轉。',
                '`auditctl -l` 輸出: ' . trim($out ?? '(empty)'),
                '於 /etc/audit/rules.d/ 加入規則（可參考 CIS Linux benchmark）。');
        }
        return $this->pass('A.5.28', '證據收集', self::SEV_MEDIUM,
            "auditd 運作中，已載入 {$ruleCount} 條規則。");
    }

    /** A.8.10 — 資訊刪除：安全刪除工具可用。 */
    private function checkSecureDeleteTools(): array
    {
        $tools = [];
        foreach (['shred', 'wipe', 'srm', 'scrub'] as $t) {
            if ($this->which($t) !== null) {
                $tools[] = $t;
            }
        }
        if (empty($tools)) {
            return $this->warn('A.8.10', '資訊刪除', self::SEV_LOW,
                '未安裝任何安全刪除工具（shred / wipe / srm / scrub）。',
                'which shred/wipe/srm/scrub 皆無。',
                '安裝：apt install coreutils secure-delete（shred 內建於 coreutils）。');
        }
        return $this->pass('A.8.10', '資訊刪除', self::SEV_LOW,
            '可用的安全刪除工具：' . implode(', ', $tools) . '。');
    }

    /** A.8.21 — 敏感服務對外暴露（資料庫 / 快取 / 訊息佇列）。 */
    private function checkSensitiveServiceExposure(): array
    {
        $sensitivePorts = [
            3306 => 'MySQL',
            5432 => 'PostgreSQL',
            6379 => 'Redis',
            11211 => 'Memcached',
            27017 => 'MongoDB',
            9200 => 'Elasticsearch',
            5984 => 'CouchDB',
            5672 => 'RabbitMQ',
            2379 => 'etcd',
        ];
        $out = $this->runCmd(['ss', '-tlnH']) ?? $this->runCmd(['ss', '-tln']);
        if ($out === null) {
            return $this->na('A.8.21-sensitive', '敏感服務暴露', '無法執行 ss。');
        }
        $exposed = [];
        foreach (preg_split('/\r?\n/', trim($out)) as $line) {
            if (preg_match('/\s(?:0\.0\.0\.0|\*|\[::\]):(\d+)\s/', $line, $m)) {
                $port = (int) $m[1];
                if (isset($sensitivePorts[$port])) {
                    $exposed[] = "{$sensitivePorts[$port]}({$port})";
                }
            }
        }
        if (empty($exposed)) {
            return $this->pass('A.8.21-sensitive', '敏感服務暴露', self::SEV_HIGH,
                '未偵測到資料庫／快取／訊息佇列對外監聽。');
        }
        return $this->fail('A.8.21-sensitive', '敏感服務暴露', self::SEV_HIGH,
            '偵測到敏感服務對外暴露：' . implode('、', $exposed),
            implode(', ', $exposed),
            '改為僅綁定 127.0.0.1，或以防火牆限制來源 IP。對外請走反向代理 / VPN。');
    }

    /** A.8.22 — 網路分隔：ip_forward 衛生。 */
    private function checkIpForwardHygiene(): array
    {
        $out = $this->runCmd(['sysctl', '-n', 'net.ipv4.ip_forward']);
        $val = $out !== null ? trim($out) : null;
        if ($val === null) {
            return $this->na('A.8.22', '網路分隔', '無法讀取 net.ipv4.ip_forward。');
        }
        // 若啟用 ip_forward，必須有防火牆的 FORWARD 鏈規則；否則視為誤設。
        if ($val === '0') {
            return $this->pass('A.8.22', '網路分隔', self::SEV_LOW,
                'net.ipv4.ip_forward=0（端點主機，不作為路由器）。');
        }
        // Forwarding is on — check FORWARD chain has at least some policy.
        $forwardOut = $this->runCmd(['iptables', '-S', 'FORWARD']) ?? $this->runCmd(['nft', 'list', 'chain', 'inet', 'filter', 'forward']);
        $hasPolicy = $forwardOut !== null && trim($forwardOut) !== '' && !preg_match('/^-P FORWARD ACCEPT\s*$/m', trim($forwardOut));
        if ($hasPolicy) {
            return $this->pass('A.8.22', '網路分隔', self::SEV_LOW,
                'ip_forward=1 且 FORWARD 鏈已設定規則（符合路由／分隔用途）。');
        }
        return $this->warn('A.8.22', '網路分隔', self::SEV_MEDIUM,
            'ip_forward 啟用但 FORWARD 鏈無限制規則（預設 ACCEPT）。',
            'net.ipv4.ip_forward=1；iptables -S FORWARD 顯示預設 ACCEPT。',
            '若非路由器，sysctl -w net.ipv4.ip_forward=0；若為路由器，於 FORWARD 鏈加上來源／目的限制。');
    }

    /** A.8.32 — 變更管理：/etc 版本控制。 */
    private function checkEtcUnderVersionControl(): array
    {
        $signals = [];
        if (is_dir('/etc/.git')) {
            $signals[] = '/etc/.git';
        }
        if (is_dir('/etc/.bzr')) {
            $signals[] = '/etc/.bzr';
        }
        if (is_dir('/etc/.hg')) {
            $signals[] = '/etc/.hg';
        }
        if ($this->which('etckeeper') !== null) {
            $signals[] = 'etckeeper(bin)';
        }
        if (empty($signals)) {
            return $this->warn('A.8.32', '變更管理', self::SEV_LOW,
                '/etc 不在版本控制之下，設定變更無軌跡。',
                '未偵測到 /etc/.git、/etc/.bzr、/etc/.hg 或 etckeeper。',
                '安裝 etckeeper：apt install etckeeper，其會自動把 /etc 放入 git。');
        }
        return $this->pass('A.8.32', '變更管理', self::SEV_LOW,
            '/etc 位於版本控制之下。', implode(', ', $signals));
    }

    /** A.5.31 — 套件更新積壓。 */
    private function checkPendingSecurityUpdates(): array
    {
        // Debian/Ubuntu
        if ($this->which('apt') !== null) {
            $out = $this->runCmd(['apt', 'list', '--upgradable'], 15);
            if ($out === null) {
                return $this->na('A.5.31', '套件更新積壓', 'apt list --upgradable 執行失敗。');
            }
            $lines = preg_split('/\r?\n/', trim($out));
            // First line is "Listing..." header
            $upgradable = max(0, count($lines) - 1);
            $security = 0;
            foreach ($lines as $l) {
                if (stripos($l, 'security') !== false) {
                    $security++;
                }
            }
            if ($upgradable === 0) {
                return $this->pass('A.5.31', '套件更新積壓', self::SEV_MEDIUM, '沒有可升級的套件。');
            }
            if ($security > 0) {
                return $this->fail('A.5.31', '套件更新積壓', self::SEV_HIGH,
                    "有 {$security} 個安全性更新待安裝（總計 {$upgradable} 個可升級）。",
                    "apt list --upgradable 中 {$security} 行含 'security'。",
                    'apt upgrade 或 unattended-upgrades 啟用。');
            }
            return $this->warn('A.5.31', '套件更新積壓', self::SEV_MEDIUM,
                "有 {$upgradable} 個可升級的套件（未偵測到安全標記，可能僅功能性）。",
                '',
                '於維運視窗執行 apt upgrade 或開啟自動更新。');
        }
        if ($this->which('dnf') !== null) {
            $out = $this->runCmd(['dnf', 'check-update', '--security'], 15);
            if ($out === null) {
                // dnf returns non-zero when updates exist
            }
            return $this->pass('A.5.31', '套件更新積壓', self::SEV_MEDIUM,
                '偵測到 dnf；請改用 dnf-automatic 管理（A.8.8 已檢查）。');
        }
        return $this->na('A.5.31', '套件更新積壓', '非 Debian / RHEL 家族，略過。');
    }

    /** A.8.5 — SSH 金鑰檔權限。 */
    private function checkSshKeyFilePermissions(): array
    {
        $issues = [];
        $roots = ['/root'];
        foreach (@glob('/home/*') ?: [] as $h) {
            if (is_dir($h)) {
                $roots[] = $h;
            }
        }
        foreach ($roots as $home) {
            $sshDir = $home . '/.ssh';
            if (!is_dir($sshDir)) {
                continue;
            }
            $dirMode = fileperms($sshDir) & 0777;
            if (($dirMode & 0077) !== 0) {
                $issues[] = "{$sshDir} mode=" . sprintf('%04o', $dirMode) . '（應 0700）';
            }
            $ak = $sshDir . '/authorized_keys';
            if (is_file($ak)) {
                $m = fileperms($ak) & 0777;
                if (($m & 0077) !== 0) {
                    $issues[] = "{$ak} mode=" . sprintf('%04o', $m) . '（應 0600）';
                }
            }
            foreach (@glob($sshDir . '/id_*') ?: [] as $pk) {
                if (str_ends_with($pk, '.pub')) {
                    continue;
                }
                $m = fileperms($pk) & 0777;
                if (($m & 0077) !== 0) {
                    $issues[] = "{$pk} mode=" . sprintf('%04o', $m) . '（私鑰，應 0600）';
                }
            }
        }
        if (empty($issues)) {
            return $this->pass('A.8.5-perms', 'SSH 金鑰檔權限', self::SEV_HIGH,
                '所檢視的 .ssh 目錄與金鑰檔權限皆正確。');
        }
        return $this->fail('A.8.5-perms', 'SSH 金鑰檔權限', self::SEV_HIGH,
            'SSH 金鑰相關檔案權限過鬆：' . count($issues) . ' 項。',
            implode("\n", array_slice($issues, 0, 8)) . (count($issues) > 8 ? "\n…（已截斷）" : ''),
            'chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys ~/.ssh/id_*。');
    }

    /** A.8.24 — TLS 憑證到期。 */
    private function checkTlsCertExpiry(): array
    {
        if ($this->which('openssl') === null) {
            return $this->na('A.8.24-cert', 'TLS 憑證到期', '未安裝 openssl。');
        }
        $candidates = array_merge(
            @glob('/etc/letsencrypt/live/*/cert.pem') ?: [],
            @glob('/etc/letsencrypt/live/*/fullchain.pem') ?: [],
            @glob('/etc/ssl/certs/*.pem') ?: [],
            @glob('/etc/pki/tls/certs/*.pem') ?: [],
            @glob('/etc/nginx/ssl/*.pem') ?: [],
            @glob('/etc/nginx/ssl/*.crt') ?: [],
        );
        $candidates = array_values(array_unique(array_filter($candidates, 'is_file')));
        if (empty($candidates)) {
            return $this->na('A.8.24-cert', 'TLS 憑證到期', '未找到常見路徑下的 TLS 憑證。');
        }
        $nowTs = time();
        $warning = [];
        $expired = [];
        $inspected = 0;
        foreach (array_slice($candidates, 0, 30) as $cert) {
            $out = $this->runCmd(['openssl', 'x509', '-in', $cert, '-enddate', '-noout']);
            if ($out === null || !preg_match('/notAfter=(.+)/', $out, $m)) {
                continue;
            }
            $inspected++;
            $expiresAt = strtotime(trim($m[1]));
            if (!$expiresAt) {
                continue;
            }
            $daysLeft = (int) floor(($expiresAt - $nowTs) / 86400);
            if ($daysLeft < 0) {
                $expired[] = basename($cert) . ' (過期 ' . abs($daysLeft) . ' 天)';
            } elseif ($daysLeft <= 30) {
                $warning[] = basename($cert) . " ({$daysLeft} 天後到期)";
            }
        }
        if (!empty($expired)) {
            return $this->fail('A.8.24-cert', 'TLS 憑證到期', self::SEV_HIGH,
                '有 ' . count($expired) . ' 個 TLS 憑證已過期。',
                implode("\n", array_slice($expired, 0, 5)),
                '續簽／更新：certbot renew，或更新購買憑證。');
        }
        if (!empty($warning)) {
            return $this->warn('A.8.24-cert', 'TLS 憑證到期', self::SEV_MEDIUM,
                '有 ' . count($warning) . ' 個 TLS 憑證 30 天內到期。',
                implode("\n", array_slice($warning, 0, 5)),
                '儘速續簽（certbot renew）。');
        }
        return $this->pass('A.8.24-cert', 'TLS 憑證到期', self::SEV_MEDIUM,
            "檢視 {$inspected} 個憑證，皆距到期 >30 天。");
    }

    /** A.8.9 — SUID / SGID 二進位普查。 */
    private function checkSuidBinariesCensus(): array
    {
        $out = $this->runCmd(['find', '/usr/local', '/opt', '-xdev', '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')'], 12);
        if ($out === null) {
            return $this->na('A.8.9-suid', 'SUID/SGID 普查', '無法執行 find。');
        }
        $lines = array_filter(preg_split('/\r?\n/', trim($out)));
        // /usr/local and /opt are admin-managed; any SUID here is worth a human look.
        if (empty($lines)) {
            return $this->pass('A.8.9-suid', 'SUID/SGID 普查', self::SEV_LOW,
                '/usr/local 與 /opt 下沒有 SUID/SGID 二進位。');
        }
        return $this->warn('A.8.9-suid', 'SUID/SGID 普查', self::SEV_MEDIUM,
            '/usr/local 與 /opt 下找到 ' . count($lines) . ' 個 SUID/SGID 檔案，請確認必要性。',
            implode("\n", array_slice($lines, 0, 15)) . (count($lines) > 15 ? "\n…（已截斷）" : ''),
            '非必要的 SUID：chmod u-s / g-s 移除；必要者加入白名單。');
    }

    /** A.5.16 — root shell 歷史純淨。 */
    private function checkRootHistorySanitation(): array
    {
        $hist = '/root/.bash_history';
        if (!file_exists($hist)) {
            return $this->pass('A.5.16-hist', 'root 歷史純淨', self::SEV_LOW,
                '/root/.bash_history 不存在（可能導向 /dev/null）。');
        }
        $size = @filesize($hist);
        $perms = fileperms($hist) & 0777;
        $issues = [];
        if ($size > 0 && is_link($hist)) {
            // ok, symlink
        } elseif ($size > 0) {
            $issues[] = "size={$size} bytes（建議定期清空或導向 /dev/null）";
        }
        if (($perms & 0077) !== 0) {
            $issues[] = 'mode=' . sprintf('%04o', $perms) . '（應 0600）';
        }
        if (empty($issues)) {
            return $this->pass('A.5.16-hist', 'root 歷史純淨', self::SEV_LOW,
                '/root/.bash_history 檔案權限正確且可接受。');
        }
        return $this->warn('A.5.16-hist', 'root 歷史純淨', self::SEV_LOW,
            'root shell 歷史檔有風險：' . implode('；', $issues),
            "path={$hist}",
            'chmod 600 ~/.bash_history 或 ln -sf /dev/null ~/.bash_history。');
    }

    /** A.8.14 — 儲存備援（RAID / LVM mirror）。 */
    private function checkStorageRedundancy(): array
    {
        $signals = [];
        $md = @file_get_contents('/proc/mdstat');
        if ($md !== false && preg_match_all('/md\d+\s*:\s*active\s+(raid\d+)/', $md, $m)) {
            foreach ($m[1] as $lvl) {
                $signals[] = "mdraid:{$lvl}";
            }
        }
        $lvs = $this->runCmd(['lvs', '--noheadings', '-o', 'lv_name,segtype']);
        if ($lvs !== null) {
            foreach (preg_split('/\r?\n/', trim($lvs)) as $line) {
                if (preg_match('/\s+(mirror|raid[0-9]+)\b/', $line, $m)) {
                    $signals[] = 'lvm:' . $m[1];
                }
            }
        }
        $zp = $this->runCmd(['zpool', 'status']);
        if ($zp !== null && preg_match('/\b(mirror|raidz\d*)\b/', $zp)) {
            $signals[] = 'zfs';
        }
        if (empty($signals)) {
            return $this->warn('A.8.14', '儲存備援', self::SEV_LOW,
                '未偵測到 RAID / LVM mirror / ZFS 冗餘。',
                '/proc/mdstat / lvs / zpool status 皆無 mirror/raid 字樣。',
                '對關鍵資料磁碟啟用 mdraid、LVM mirror 或 ZFS。');
        }
        return $this->pass('A.8.14', '儲存備援', self::SEV_LOW,
            '偵測到冗餘儲存：' . implode(', ', array_unique($signals)) . '。');
    }

    /** A.8.3 — 家目錄權限。 */
    private function checkHomeDirPermissions(): array
    {
        $bad = [];
        foreach (@glob('/home/*') ?: [] as $h) {
            if (!is_dir($h)) {
                continue;
            }
            $m = fileperms($h) & 0777;
            // 0700/0750/0755 acceptable; other-readable is weak but common; world-writable is not.
            if (($m & 0002) !== 0) {
                $bad[] = basename($h) . ' mode=' . sprintf('%04o', $m) . '（world-writable）';
            } elseif (($m & 0007) !== 0 && ($m & 0005) !== 0005) {
                // other has rights beyond simple r-x — flag
                $bad[] = basename($h) . ' mode=' . sprintf('%04o', $m);
            }
        }
        if (empty($bad)) {
            return $this->pass('A.8.3-home', '家目錄權限', self::SEV_MEDIUM,
                '/home/* 權限皆未對 other 開放過多權限。');
        }
        return $this->warn('A.8.3-home', '家目錄權限', self::SEV_MEDIUM,
            '部分家目錄權限過鬆：' . count($bad) . ' 項。',
            implode("\n", array_slice($bad, 0, 10)),
            'chmod 0700 /home/<user>（或 0750 若群組需存取）。');
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private function pass(string $id, string $name, string $severity, string $description, string $evidence = ''): array
    {
        return $this->entry($id, $name, self::STATUS_PASS, $severity, $description, $evidence, '');
    }

    private function fail(string $id, string $name, string $severity, string $description, string $evidence = '', string $recommendation = ''): array
    {
        return $this->entry($id, $name, self::STATUS_FAIL, $severity, $description, $evidence, $recommendation);
    }

    private function warn(string $id, string $name, string $severity, string $description, string $evidence = '', string $recommendation = ''): array
    {
        return $this->entry($id, $name, self::STATUS_WARNING, $severity, $description, $evidence, $recommendation);
    }

    private function na(string $id, string $name, string $description): array
    {
        return $this->entry($id, $name, self::STATUS_NOT_APPLICABLE, self::SEV_LOW, $description, '', '');
    }

    private function entry(string $id, string $name, string $status, string $severity, string $description, string $evidence, string $recommendation): array
    {
        return [
            'control_id' => $id,
            'control_name' => $name,
            'status' => $status,
            'severity' => $severity,
            'description' => $description,
            'evidence' => $evidence,
            'recommendation' => $recommendation,
        ];
    }

    private function summarize(array $checks): array
    {
        $counts = [
            self::STATUS_PASS => 0,
            self::STATUS_FAIL => 0,
            self::STATUS_WARNING => 0,
            self::STATUS_NOT_APPLICABLE => 0,
        ];
        foreach ($checks as $c) {
            $counts[$c['status']]++;
        }

        $applicable = count($checks) - $counts[self::STATUS_NOT_APPLICABLE];
        // 得分：pass = 1.0、warning = 0.5、fail = 0。
        $score = $applicable > 0
            ? round((($counts[self::STATUS_PASS] + 0.5 * $counts[self::STATUS_WARNING]) / $applicable) * 100, 1)
            : 0.0;

        return [
            'framework' => 'ISO/IEC 27001:2022',
            'checked_at' => now()->toIso8601String(),
            'hostname' => gethostname() ?: null,
            'os' => php_uname('s') . ' ' . php_uname('r'),
            'overall_score' => $score,
            'total_checks' => count($checks),
            'applicable_checks' => $applicable,
            'passed_checks' => $counts[self::STATUS_PASS],
            'failed_checks' => $counts[self::STATUS_FAIL],
            'warning_checks' => $counts[self::STATUS_WARNING],
            'not_applicable_checks' => $counts[self::STATUS_NOT_APPLICABLE],
            'checks' => $checks,
        ];
    }

    private function matchStr(string $content, string $pattern): ?string
    {
        return preg_match($pattern, $content, $m) ? trim($m[1]) : null;
    }

    private function matchInt(string $content, string $pattern): ?int
    {
        $v = $this->matchStr($content, $pattern);
        return $v !== null ? (int) $v : null;
    }

    private function which(string $bin): ?string
    {
        $out = $this->runCmd(['which', $bin]);
        if ($out === null) {
            return null;
        }
        $path = trim($out);
        return $path !== '' && is_executable($path) ? $path : null;
    }

    private function isServiceActive(string $name): bool
    {
        $out = $this->runCmd(['systemctl', 'is-active', $name]);
        if ($out !== null && trim($out) === 'active') {
            return true;
        }
        return false;
    }

    private function pgrep(string $name): bool
    {
        $out = $this->runCmd(['pgrep', '-x', $name]);
        return $out !== null && trim($out) !== '';
    }

    private function runCmd(array $argv, int $timeout = 5): ?string
    {
        try {
            $p = new Process($argv);
            $p->setTimeout($timeout);
            $p->run();
            return $p->isSuccessful() ? $p->getOutput() : null;
        } catch (\Throwable $e) {
            Log::debug('ComplianceAnalyzer runCmd failed', ['argv' => $argv, 'err' => $e->getMessage()]);
            return null;
        }
    }
}
