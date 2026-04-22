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
