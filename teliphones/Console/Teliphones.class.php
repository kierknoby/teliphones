<?php
namespace FreePBX\Console\Command;

require_once dirname(__DIR__) . '/SupportAdapter.php';
require_once dirname(__DIR__) . '/LocalAttestor.php';
require_once dirname(__DIR__) . '/WireGuardAgent.php';
require_once dirname(__DIR__) . '/ConnectClient.php';
require_once dirname(__DIR__) . '/Topology.php';
require_once dirname(__DIR__) . '/CheckerEvidence.php';
require_once dirname(__DIR__) . '/VerificationProbe.php';
require_once dirname(__DIR__) . '/ConnectContract.php';
require_once dirname(__DIR__) . '/ConsoleContract.php';
use FreePBX\modules\Teliphones\SupportAdapter;
use FreePBX\modules\Teliphones\LocalAttestor;
use FreePBX\modules\Teliphones\WireGuardAgent;
use FreePBX\modules\Teliphones\ConnectClient;
use FreePBX\modules\Teliphones\Topology;
use FreePBX\modules\Teliphones\CheckerEvidence;
use FreePBX\modules\Teliphones\ConnectContract;
use FreePBX\modules\Teliphones\ConsoleContract;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Teliphones extends Command
{
    private const STATE_DIR = '/var/lib/teliphones';
    private const STATE_FILE = '/var/lib/teliphones/session.json';
    private const AUDIT_FILE = '/var/log/teliphones.log';
    private const DISABLED_FILE = '/var/lib/teliphones/disabled';
    private const QUARANTINE_FILE = '/var/lib/teliphones/quarantine.json';

    protected function configure()
    {
        $this->setName('teliphones')
            ->setDescription('Manage temporary TELIPHONES support authority')
            ->addArgument('action', InputArgument::OPTIONAL, 'status|baseline|authorise|connect-request|provision|connect-confirm|peer|attest|checker-request|checker-accept|open|console-handoff|revoke|check|enable|disable|reconcile', 'status')
            ->addOption('minutes', null, InputOption::VALUE_REQUIRED, 'Support window in minutes', '60')
            ->addOption('session', null, InputOption::VALUE_REQUIRED, 'Internal session guard for expiry')
            ->addOption('peer-key', null, InputOption::VALUE_REQUIRED, 'Temporary Console-side WireGuard public key')
            ->addOption('peer-endpoint', null, InputOption::VALUE_REQUIRED, 'Temporary Console-side WireGuard endpoint host:port')
            ->addOption('ssh-key', null, InputOption::VALUE_REQUIRED, 'Session-specific Console SSH public key')
            ->addOption('topology', null, InputOption::VALUE_REQUIRED, 'Support topology: on-pbx|on-net|off-net', 'on-pbx')
            ->addOption('pbx-address', null, InputOption::VALUE_REQUIRED, 'On-PBX tunnel address CIDR proposed by Connect')
            ->addOption('peer-address', null, InputOption::VALUE_REQUIRED, 'On-PBX peer address /32 proposed by Connect')
            ->addOption('evidence-file', null, InputOption::VALUE_REQUIRED, 'Checker evidence JSON file');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            $output->writeln('<error>TELIPHONES must be managed by root.</error>');
            return Command::FAILURE;
        }

        $action = strtolower((string)$input->getArgument('action'));
        if ($action !== 'expire') {
            $this->expireIfNeeded();
        }

        switch ($action) {
            case 'authorise': return $this->authorise($input, $output);
            case 'revoke': return $this->revoke($output, 'manual');
            case 'check': return $this->check($output);
            case 'connect-request': return $this->connectRequest($output);
            case 'provision': return $this->provision($output);
            case 'connect-confirm': return $this->connectConfirm($output);
            case 'peer': return $this->peer($input, $output);
            case 'attest': return $this->attest($output);
            case 'checker-request': return $this->checkerRequest($output);
            case 'checker-accept': return $this->checkerAccept($input,$output);
            case 'open': return $this->openAccess($input, $output);
            case 'console-handoff': return $this->consoleHandoff($output);
            case 'enable': return $this->enable($output);
            case 'disable': return $this->disable($output);
            case 'reconcile': return $this->reconcile($output);
            case 'baseline': return $this->baseline($output);
            case 'status': return $this->status($output);
            case 'expire': return $this->expire($input, $output);
            default:
                $output->writeln('<error>Unknown action. Use status, baseline, check, authorise, connect-request, provision, connect-confirm, peer, attest, checker-request, checker-accept, open, console-handoff, revoke, enable, disable or reconcile.</error>');
                return Command::INVALID;
        }
    }

    private function authorise(InputInterface $input, OutputInterface $output): int
    {
        if (!$this->isTeliphonesEnabled()) {
            $output->writeln('<error>TELIPHONES is disabled. Enable it first with: fwconsole teliphones enable</error>');
            return Command::FAILURE;
        }
        if (is_file(self::QUARANTINE_FILE)) {
            $output->writeln('<error>TELIPHONES is quarantined after a failed verification or cleanup. Inspect the PBX and resolve the quarantine before authorising support.</error>');
            return Command::FAILURE;
        }
        if ($this->readState()) {
            $output->writeln('<error>A TELIPHONES session already exists. Revoke or allow it to expire before creating a new authorisation.</error>');
            return Command::FAILURE;
        }

        $minutes = filter_var($input->getOption('minutes'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 5, 'max_range' => 240]]);
        if ($minutes === false) {
            $output->writeln('<error>Duration must be between 5 and 240 minutes.</error>');
            return Command::INVALID;
        }

        if (!is_dir(self::STATE_DIR) && !mkdir(self::STATE_DIR, 0700, true) && !is_dir(self::STATE_DIR)) {
            $output->writeln('<error>Unable to create TELIPHONES state directory.</error>');
            return Command::FAILURE;
        }

        $topology = strtolower(trim((string)$input->getOption('topology')));
        if (!Topology::valid($topology)) { $output->writeln('<error>Topology must be on-pbx, on-net or off-net.</error>'); return Command::INVALID; }
        $addresses = Topology::defaultAddresses(17);
        $pbxOpt=trim((string)$input->getOption('pbx-address')); $peerOpt=trim((string)$input->getOption('peer-address'));
        if (($pbxOpt!=='' || $peerOpt!=='') && $topology!==Topology::ON_PBX) { $output->writeln('<error>PBX/peer tunnel addresses apply only to On-PBX mode.</error>'); return Command::INVALID; }
        if ($topology===Topology::ON_PBX && ($pbxOpt!=='' || $peerOpt!=='')) {
            if ($pbxOpt==='' || $peerOpt==='' || !Topology::validPair($pbxOpt,$peerOpt)) { $output->writeln('<error>Both --pbx-address and --peer-address are required and must be valid private tunnel CIDRs.</error>'); return Command::INVALID; }
            $pbxIp=explode('/',$pbxOpt,2)[0]; $peerIp=explode('/',$peerOpt,2)[0]; $prefix=(int)explode('/',$pbxOpt,2)[1]; $mask=(-1 << (32-$prefix)); $network=long2ip(ip2long($pbxIp)&$mask).'/'.$prefix;
            $addresses=['subnet'=>$network,'pbx'=>$pbxOpt,'pbx_ip'=>$pbxIp,'peer'=>$peerOpt,'peer_ip'=>$peerIp];
        }
        if ($topology===Topology::ON_PBX && (new WireGuardAgent())->collides($addresses['subnet'])) { $output->writeln('<error>Proposed support subnet overlaps existing PBX routing. Ask Connect for another private pair.</error>'); return Command::FAILURE; }

        // Re-authorisation replaces the previous grant. Its timer is harmless because expiry is session-guarded.
        $now = time();
        $state = [
            'version' => 1,
            'state' => 'authorised',
            'session_id' => bin2hex(random_bytes(16)),
            'authorised_at' => $now,
            'expires_at' => $now + ($minutes * 60),
            'transport' => 'wireguard',
            'topology' => $topology,
            'topology_label' => Topology::label($topology),
            'freepbx_major' => 17,
            'preferred_pool' => Topology::preferredPool(17),
            'addresses' => $topology===Topology::ON_PBX ? $addresses : null,
            'attested' => false,
            'checker_accepted' => false
        ];

        if (!$this->writeState($state)) {
            $output->writeln('<error>Unable to write TELIPHONES session state.</error>');
            return Command::FAILURE;
        }

        $wireguard = new WireGuardAgent();
        if (!$wireguard->prepare($state)) {
            @unlink(self::STATE_FILE);
            $this->audit('authorise-failed', $state, ['reason' => 'wireguard-prepare']);
            $output->writeln('<error>Unable to prepare the ephemeral WireGuard endpoint. Support was not authorised.</error>');
            return Command::FAILURE;
        }

        $adapter = new SupportAdapter();
        if (!$adapter->prepare($state)) {
            $wireguard->destroy();
            @unlink(self::STATE_FILE);
            $this->audit('authorise-failed', $state, ['reason' => 'adapter-prepare']);
            $output->writeln('<error>Unable to prepare the Console adapter boundary. Support was not authorised.</error>');
            return Command::FAILURE;
        }

        $attestor = new LocalAttestor();
        if (!$attestor->placeholder($state)) {
            $adapter->destroy();
            $wireguard->destroy();
            (new LocalAttestor())->destroy(); (new CheckerEvidence())->destroy();
            @unlink(self::STATE_FILE);
            $this->audit('authorise-failed', $state, ['reason' => 'attestation-state']);
            $output->writeln('<error>Unable to initialise local verification state. Support was not authorised.</error>');
            return Command::FAILURE;
        }

        if (!$this->scheduleExpiry($state, $minutes)) {
            $adapter->destroy();
            $wireguard->destroy();
            $attestor->destroy();
            @unlink(self::STATE_FILE);
            $this->audit('authorise-failed', $state, ['reason' => 'expiry-scheduler']);
            $output->writeln('<error>Unable to schedule local expiry. Support was not authorised.</error>');
            return Command::FAILURE;
        }

        $this->audit('authorised', $state, ['minutes' => $minutes]);
        $output->writeln('<info>TELIPHONES support authority created.</info>');
        $output->writeln('Session: ' . $state['session_id']);
        $output->writeln('Support topology: ' . Topology::label($topology));
        $output->writeln('Preferred address pool: ' . Topology::preferredPool(17));
        $output->writeln('Transport: ' . ($topology===Topology::ON_PBX ? 'temporary WireGuard endpoint prepared on PBX' : 'external Connect path expected; PBX networking untouched'));
        $output->writeln('Local verification: pending; Checker evidence is required before support-ready');
        $output->writeln('Expires: ' . date(DATE_RFC3339, $state['expires_at']));
        $output->writeln('Expiry is enforced locally by this PBX. No remote access opens until Connect is established, local verification passes, and Checker evidence is accepted.');
        return Command::SUCCESS;
    }

    private function expire(InputInterface $input, OutputInterface $output): int
    {
        $expected = trim((string)$input->getOption('session'));
        if ($expected === '' || !preg_match('/^[a-f0-9]{32}$/', $expected)) {
            return Command::INVALID;
        }
        $state = $this->readState();
        if (!$state || !hash_equals((string)($state['session_id'] ?? ''), $expected)) {
            return Command::SUCCESS; // stale timer: never touch a newer grant
        }
        if (time() < (int)($state['expires_at'] ?? 0)) {
            return Command::SUCCESS;
        }
        $localCleanup = $this->cleanupLocal($state);
        $this->audit('expired', $state);
        $remoteCleanup = $this->cleanupRemote($state);
        if (!$localCleanup || !$remoteCleanup) {
            return Command::FAILURE;
        }
        return Command::SUCCESS;
    }

    private function revoke(OutputInterface $output, string $reason): int
    {
        $state = $this->readState();
        $cleanupOk = $state ? $this->cleanupLocal($state) : $this->cleanupOrphanedLocalState();
        $remoteCleanup = $state ? $this->cleanupRemote($state) : $this->cleanupOrphanedRemoteState();
        $cleanupOk = $cleanupOk && $remoteCleanup;
        if (!$cleanupOk) {
            $output->writeln('<error>Local authority was revoked first, but local or gateway cleanup failed. Inspect the PBX and retry gateway cleanup before re-authorising.</error>');
        }
        if (is_file(self::STATE_FILE) && !unlink(self::STATE_FILE)) {
            $output->writeln('<error>Unable to remove TELIPHONES session state.</error>');
            return Command::FAILURE;
        }
        if ($state) $this->audit('revoked', $state, ['reason' => $reason, 'gateway_cleanup' => $remoteCleanup ? 'complete' : 'pending']);
        $output->writeln('<info>TELIPHONES support authority revoked.</info>');
        $output->writeln('TELIPHONES attempted destruction of all locally owned ephemeral support state.');
        return $cleanupOk ? Command::SUCCESS : Command::FAILURE;
    }

    private function connectRequest(OutputInterface $output): int
    {
        $state=$this->readState(); if(!$state||time()>=(int)($state['expires_at']??0)){ $output->writeln('<error>No current TELIPHONES authorisation exists.</error>'); return Command::FAILURE; }
        $pub=(new WireGuardAgent())->publicKey();
        $output->writeln(json_encode((new ConnectContract())->request($state,$pub),JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)); return Command::SUCCESS;
    }

    private function checkerRequest(OutputInterface $output): int
    {
        $state=$this->readState(); $local=(new LocalAttestor())->state();
        if(!$state||($state['state']??'')!=='connected'||!$local||empty($local['verified'])){ $output->writeln('<error>WireGuard transport and PBX-local verification must pass before the restricted Checker probe is enabled.</error>'); return Command::FAILURE; }
        $challenge=(new CheckerEvidence())->challenge($state);
        if(!(new VerificationProbe())->start($state,$challenge)){
            (new CheckerEvidence())->destroy();
            $output->writeln('<error>Unable to start the restricted, session-bound Checker probe. No engineer services have been opened.</error>');return Command::FAILURE;
        }
        $output->writeln(json_encode($challenge,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)); return Command::SUCCESS;
    }

    private function checkerAccept(InputInterface $input,OutputInterface $output): int
    {
        $state=$this->readState(); if(!$state){$output->writeln('<error>No current TELIPHONES authorisation exists.</error>');return Command::FAILURE;}
        $file=trim((string)$input->getOption('evidence-file')); if($file===''||!is_readable($file)){$output->writeln('<error>--evidence-file must name a readable Checker JSON file.</error>');return Command::INVALID;}
        $e=json_decode((string)file_get_contents($file),true); if(!is_array($e)){$output->writeln('<error>Checker evidence is not valid JSON.</error>');return Command::INVALID;}
        $r=(new CheckerEvidence())->accept($state,$e); if(empty($r['accepted'])){$this->audit('checker-rejected',$state,['errors'=>$r['errors']]);$output->writeln('<error>Checker evidence rejected: '.implode(', ',$r['errors']).'</error>');return Command::FAILURE;}
        if(!(new VerificationProbe())->destroy()){$this->audit('checker-probe-cleanup-failed',$state);$output->writeln('<error>Checker evidence passed but the restricted probe could not be stopped; engineer access remains closed.</error>');return Command::FAILURE;}
        if(!(new ConnectClient())->activate($state)){$this->audit('gateway-activation-failed',$state);$output->writeln('<error>Checker evidence passed but Connect could not activate the authorised engineer service profile.</error>');return Command::FAILURE;}
        $state['checker_accepted']=true;$state['state']='verified';$state['verified_at']=time();if(!$this->writeState($state)){$this->cleanupLocal($state);$this->cleanupRemote($state);return Command::FAILURE;}$this->audit('checker-accepted',$state);$output->writeln('<info>Checker evidence accepted; engineer services are active. SSH remains closed until the customer opens it.</info>');return Command::SUCCESS;
    }

    private function consoleHandoff(OutputInterface $output): int
    {
        $state=$this->readState(); $adapter=(new SupportAdapter())->state(); if(!$state||!$adapter||empty($adapter['support_ready'])||!(new CheckerEvidence())->accepted($state)){$output->writeln('<error>Console handoff is unavailable until TELIPHONES is READY.</error>');return Command::FAILURE;}
        $output->writeln(json_encode((new ConsoleContract())->handoff($state,$adapter),JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));return Command::SUCCESS;
    }

    private function provision(OutputInterface $output): int
    {
        $state=$this->readState(); $wg=new WireGuardAgent();
        if(!$state || time()>=(int)($state['expires_at']??0)){ $output->writeln('<error>No current TELIPHONES authorisation exists.</error>'); return Command::FAILURE; }
        $pub=$wg->publicKey()??''; if(($state['topology']??Topology::ON_PBX)===Topology::ON_PBX && !$pub){ $output->writeln('<error>PBX WireGuard identity is not prepared.</error>'); return Command::FAILURE; }
        $broker=new ConnectClient(); if(!$broker->ready()){ $output->writeln('<error>Connect is not enrolled/configured on this PBX.</error>'); return Command::FAILURE; }
        $remote=$broker->provision($state,$pub); if(!$remote){ $this->audit('remote-provision-failed',$state); $output->writeln('<error>Connect could not create the temporary support environment.</error>'); return Command::FAILURE; }
        if(($state['topology']??Topology::ON_PBX)===Topology::ON_PBX && !$wg->configurePeer($state,$remote['peer_public_key'],$remote['peer_endpoint'],(array)($remote['engineer_addresses']??[]),(array)($remote['checker_addresses']??[]))){ $this->cleanupLocal($state); $this->cleanupRemote($state); $this->audit('remote-provision-failed',$state,['reason'=>'peer-config']); $output->writeln('<error>Connect created the support environment but local peer setup failed; local access was removed before gateway cleanup was requested.</error>'); return Command::FAILURE; }
        $state['state']=(($state['topology']??Topology::ON_PBX)===Topology::ON_PBX?'peer_configured':'path_provisioned'); $state['remote_id']=$remote['remote_id'];
        if(!$this->writeState($state)){
            $this->cleanupLocal($state); $this->cleanupRemote($state);
            $this->audit('remote-provision-failed',$state,['reason'=>'session-state-write']);
            $output->writeln('<error>Connect provisioned the gateway, but TELIPHONES could not persist the session. Local state was removed and gateway cleanup was requested.</error>');
            return Command::FAILURE;
        }
        $this->audit('remote-provisioned',$state,['remote_id'=>$remote['remote_id']]);
        $output->writeln('<info>Connect support environment created.</info>');
        $output->writeln((($state['topology']??Topology::ON_PBX)===Topology::ON_PBX?'WireGuard peer configured on PBX.':'External support path created by Connect; PBX networking unchanged.').' Support remains closed until attestation passes.'); return Command::SUCCESS;
    }

    private function connectConfirm(OutputInterface $output): int
    {
        $state=$this->readState();$remote=(new ConnectClient())->state();
        if(!$state||!$remote||!hash_equals((string)($state['session_id']??''),(string)($remote['session_id']??''))||time()>=(int)($state['expires_at']??0)){
            $output->writeln('<error>A current provisioned TELIPHONES session is required.</error>');return Command::FAILURE;
        }
        $wg=new WireGuardAgent();
        if(!$wg->handshakeCurrent((string)($remote['peer_public_key']??''))){
            $output->writeln('<error>The PBX WireGuard peer has not completed a fresh authenticated handshake.</error>');return Command::FAILURE;
        }
        if(!(new ConnectClient())->confirm($state)){
            $output->writeln('<error>Connect could not confirm the tunnel handshake. Checker-only access remains closed.</error>');return Command::FAILURE;
        }
        $state['state']='connected';$state['connected_at']=time();
        if(!$this->writeState($state)){$this->cleanupLocal($state);$this->cleanupRemote($state);return Command::FAILURE;}
        $this->audit('transport-connected',$state);
        $output->writeln('<info>WireGuard transport connected. Only the restricted Checker probe is reachable; engineer services remain closed.</info>');
        return Command::SUCCESS;
    }

    private function peer(InputInterface $input, OutputInterface $output): int
    {
        $current=$this->readState(); if($current && ($current['topology']??Topology::ON_PBX)!==Topology::ON_PBX){ $output->writeln('<error>Manual peer injection applies only to On-PBX topology.</error>'); return Command::FAILURE; }
        if (!$this->isTeliphonesEnabled()) { $output->writeln('<error>TELIPHONES is disabled.</error>'); return Command::FAILURE; }
        $state = $this->readState();
        if (!$state || time() >= (int)($state['expires_at'] ?? 0)) {
            $output->writeln('<error>No current TELIPHONES authorisation exists.</error>');
            return Command::FAILURE;
        }
        $key = trim((string)$input->getOption('peer-key'));
        $endpoint = trim((string)$input->getOption('peer-endpoint'));
        if ($key === '' && $endpoint === '') { $remote=(new ConnectClient())->state(); if($remote){ $key=(string)($remote['peer_public_key']??''); $endpoint=(string)($remote['peer_endpoint']??''); } }
        if ($key === '' || $endpoint === '') {
            $output->writeln('<error>Both --peer-key and --peer-endpoint are required.</error>');
            return Command::INVALID;
        }
        $wg = new WireGuardAgent();
        if (!$wg->configurePeer($state, $key, $endpoint)) {
            $wg->destroy();
            $this->audit('peer-config-failed', $state);
            $output->writeln('<error>Temporary support peer configuration failed. Ephemeral WireGuard state was destroyed.</error>');
            return Command::FAILURE;
        }
        $this->audit('peer-configured', $state, ['endpoint' => $endpoint]);
        $output->writeln('<info>Temporary support WireGuard peer configured.</info>');
        $output->writeln('Allowed peer address is session-scoped and validated by TELIPHONES; no default route is accepted.');
        $output->writeln('Support remains NOT READY until PBX-local verification and independent Checker evidence pass.');
        return Command::SUCCESS;
    }


    private function attest(OutputInterface $output): int
    {
        $state=$this->readState(); $wg=new WireGuardAgent(); $peer=$wg->peer(); $wgState=$wg->state();
        if(!$state){ $output->writeln('<error>A current TELIPHONES authorisation is required.</error>'); return Command::FAILURE; }
        if(($state['topology']??Topology::ON_PBX)===Topology::ON_PBX && (!$peer || !$wgState)){ $output->writeln('<error>On-PBX local verification requires a configured WireGuard peer.</error>'); return Command::FAILURE; }
        $result=(new LocalAttestor())->verify($state,$wgState??[],$peer??[]);
        if(empty($result['verified'])) {
            $this->cleanupLocal($state);
            $this->cleanupRemote($state);
            $q=['time'=>date(DATE_RFC3339),'session_id'=>$state['session_id']??null,'reason'=>'local-verification-failed','checks'=>$result['mandatory_checks']??[]];
            @file_put_contents(self::QUARANTINE_FILE,json_encode($q,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX); @chmod(self::QUARANTINE_FILE,0600);
            $this->audit('quarantined',$state,['reason'=>'local-verification-failed','checks'=>$result['mandatory_checks']??[]]);
            $output->writeln('<error>PBX-local verification FAILED. Tunnel and support authority were destroyed.</error>');
            $output->writeln('A fresh local root authorisation is required.'); return Command::FAILURE;
        }
        $state['state']='locally_verified'; $state['attested']=true; $state['attested_at']=time(); $this->writeState($state);
        $this->audit('local-verified',$state); $output->writeln('<info>PBX-local verification PASSED.</info>');
        $output->writeln('Support access remains closed until independent Checker evidence is accepted and root opens the Console adapter.'); return Command::SUCCESS;
    }

    private function openAccess(InputInterface $input, OutputInterface $output): int
    {
        $state=$this->readState(); $att=(new LocalAttestor())->state();
        if(!$state || empty($state['attested']) || !$att || empty($att['verified']) || !hash_equals((string)($state['session_id']??''),(string)($att['session_id']??''))) {
            $output->writeln('<error>PBX-local verification has not passed for this session.</error>'); return Command::FAILURE;
        }
        if(!(new CheckerEvidence())->accepted($state)) { $output->writeln('<error>Checker evidence has not been accepted for this session.</error>'); return Command::FAILURE; }
        $key=trim((string)$input->getOption('ssh-key')); if($key===''){ $remote=(new ConnectClient())->state(); if($remote)$key=(string)($remote['ssh_public_key']??''); } if($key===''){ $output->writeln('<error>--ssh-key is required.</error>'); return Command::INVALID; }
        $adapter=new SupportAdapter(); if(!$adapter->open($state,$key,$remote['ssh_engineer_address']??null,(array)($remote['engineer_addresses']??[]))){ $output->writeln('<error>Unable to open the dedicated temporary support SSH service.</error>'); return Command::FAILURE; }
        $state['state']='ready'; $state['checker_accepted']=true; $state['ready_at']=time(); if(!$this->writeState($state)){ $adapter->destroy(); return Command::FAILURE; }
        $this->audit('support-ready',$state); $output->writeln('<info>TELIPHONES support is READY.</info>');
        $ad=(new SupportAdapter())->state(); $output->writeln('Dedicated SSH: '.($ad['listen_address']??'support address').':'.($ad['port']??22222).', public-key only, source restricted to '.($ad['source_address']??'authorised support peer').'.'); return Command::SUCCESS;
    }

    private function check(OutputInterface $output): int
    {
        if (!$this->hasSystemdRun()) {
            $output->writeln('<error>Local expiry scheduler: systemd-run unavailable</error>');
            return Command::FAILURE;
        }
        $wg = (new WireGuardAgent())->toolingReady();
        $output->writeln($wg ? '<info>WireGuard tooling: detected</info>' : '<comment>WireGuard tooling: not ready (requires wg and /usr/sbin/ip)</comment>');
        $output->writeln('<info>Local expiry scheduler: ready</info>');
        $output->writeln('' . ((new ConnectClient())->ready() ? '<info>Connect: enrolled and ready</info>' : '<comment>Connect: not enrolled; manual peer mode remains available</comment>') . '');
        $output->writeln(is_executable('/usr/sbin/sshd') ? '<info>Dedicated SSH adapter: available</info>' : '<comment>Dedicated SSH adapter: sshd unavailable</comment>');
        $output->writeln('<info>PBX-local verifier: installed (no external probing)</info>');
        $output->writeln('<info>Checker contract: external positive/negative evidence required</info>');
        return Command::SUCCESS;
    }

    private function baseline(OutputInterface $output): int
    {
        $run = static function (string $command): array {
            $lines = []; $rc = 0;
            exec($command . ' 2>/dev/null', $lines, $rc);
            return ['rc' => $rc, 'lines' => $lines];
        };
        $state = $this->readState();
        $adapter = (new SupportAdapter())->state();
        $wg = (new WireGuardAgent())->state();
        $snapshot = [
            'schema' => 'teliphones-baseline/1',
            'captured_at' => time(),
            'hostname' => gethostname() ?: null,
            'teliphones' => [
                'enabled' => $this->isTeliphonesEnabled(),
                'active_session' => $state !== null,
                'session_state' => $state['state'] ?? null,
                'topology' => $state['topology'] ?? null,
                'expires_at' => $state['expires_at'] ?? null,
                'wireguard_present' => $wg !== null,
                'console_adapter_present' => $adapter !== null,
                'console_ready' => (bool)($adapter['support_ready'] ?? false),
                'quarantined' => is_file(self::QUARANTINE_FILE),
            ],
            'system' => [
                'addresses' => $run('/usr/sbin/ip -brief address show'),
                'routes_v4' => $run('/usr/sbin/ip -4 route show table main'),
                'rules_v4' => $run('/usr/sbin/ip -4 rule show'),
                'listeners' => $run('/usr/bin/ss -H -lntup'),
                'wg_teliphones_link' => $run('/usr/sbin/ip -details link show dev wg-teliphones'),
            ],
        ];
        // Deliberately excludes keys, credentials, configuration-file contents and unrelated process environments.
        $output->writeln(json_encode($snapshot, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        return Command::SUCCESS;
    }

    private function status(OutputInterface $output): int
    {
        $output->writeln('TELIPHONES module: ' . ($this->isTeliphonesEnabled() ? 'enabled' : 'disabled'));
        if (is_readable(self::QUARANTINE_FILE)) $output->writeln('Support quarantine: PRESENT - fresh root authorisation required');
        $remoteState = (new ConnectClient())->state();
        $output->writeln('Connect environment: ' . ($remoteState ? 'provisioned' : 'none'));
        $adapterState = (new SupportAdapter())->state();
        $wireguard = new WireGuardAgent();
        $wgState = $wireguard->state();
        $attestation = (new LocalAttestor())->state();
        $output->writeln('Console adapter: ' . ($adapterState ? 'prepared' : 'off'));
        $output->writeln('Support WireGuard: ' . (!$wgState ? 'off' : (($wgState['interface_up'] ?? false) ? 'interface up' : 'prepared, awaiting peer')));
        if ($wgState && !empty($wgState['public_key'])) $output->writeln('PBX WireGuard public key: ' . $wgState['public_key']);
        $output->writeln('PBX-local verification: ' . ($attestation ? (($attestation['verified'] ?? false) ? 'verified' : 'pending') : 'off'));
        $checker=(new CheckerEvidence())->state();
        $output->writeln('Checker evidence: '.($checker ? (($checker['accepted']??false)?'accepted':'rejected/pending') : 'none'));
        $state = $this->readState();
        if (!$state) {
            $output->writeln('TELIPHONES support: off');
            return Command::SUCCESS;
        }
        $output->writeln('TELIPHONES support: ' . ($state['state'] ?? 'unknown'));
        $output->writeln('Support topology: ' . ($state['topology_label'] ?? Topology::label($state['topology']??Topology::ON_PBX)));
        $output->writeln('Preferred address pool: ' . ($state['preferred_pool'] ?? Topology::preferredPool(17)));
        if(!empty($state['addresses'])) $output->writeln('Session addresses: PBX '.($state['addresses']['pbx']??'?').' / peer '.($state['addresses']['peer']??'?'));
        $ready = $adapterState && !empty($adapterState['support_ready']) && $attestation && !empty($attestation['verified']) && (new CheckerEvidence())->accepted($state);
        $output->writeln('Support ready: ' . ($ready ? 'YES' : 'NO'));
        $output->writeln('Session: ' . ($state['session_id'] ?? 'unknown'));
        $output->writeln('Expires: ' . date(DATE_RFC3339, (int)$state['expires_at']));
        $output->writeln('Remaining: ' . max(0, (int)$state['expires_at'] - time()) . ' seconds');
        return Command::SUCCESS;
    }

    private function enable(OutputInterface $output): int
    {
        if (is_file(self::DISABLED_FILE) && !@unlink(self::DISABLED_FILE)) {
            $output->writeln('<error>Unable to enable TELIPHONES.</error>');
            return Command::FAILURE;
        }
        $this->auditSimple('enabled');
        $output->writeln('<info>TELIPHONES enabled.</info>');
        $output->writeln('Support remains off until local root explicitly authorises a support window.');
        return Command::SUCCESS;
    }

    private function disable(OutputInterface $output): int
    {
        if (!is_dir(self::STATE_DIR) && !@mkdir(self::STATE_DIR, 0700, true) && !is_dir(self::STATE_DIR)) {
            $output->writeln('<error>Unable to create TELIPHONES state directory.</error>');
            return Command::FAILURE;
        }
        if (file_put_contents(self::DISABLED_FILE, "disabled\n", LOCK_EX) === false) {
            $output->writeln('<error>Unable to disable TELIPHONES.</error>');
            return Command::FAILURE;
        }
        @chmod(self::DISABLED_FILE, 0600);
        $state = $this->readState();
        $cleanupOk = $state ? $this->cleanupLocal($state) : $this->cleanupOrphanedLocalState();
        if (is_file(self::STATE_FILE) && !@unlink(self::STATE_FILE)) {
            $cleanupOk = false;
        }
        $remoteCleanup = $state ? $this->cleanupRemote($state) : $this->cleanupOrphanedRemoteState();
        $cleanupOk = $cleanupOk && $remoteCleanup;
        if ($state) $this->audit('revoked', $state, ['reason' => 'module-disabled', 'gateway_cleanup' => $remoteCleanup ? 'complete' : 'pending']);
        $this->auditSimple('disabled');
        $output->writeln($cleanupOk ? '<info>TELIPHONES disabled.</info>' : '<error>TELIPHONES is disabled and local access has been removed; cleanup is incomplete.</error>');
        $output->writeln('TELIPHONES attempted destruction of all locally owned ephemeral support state.');
        return $cleanupOk ? Command::SUCCESS : Command::FAILURE;
    }

    private function reconcile(OutputInterface $output): int
    {
        if (!$this->isTeliphonesEnabled()) {
            $state = $this->readState();
            $localCleanup = $state ? $this->cleanupLocal($state) : $this->cleanupOrphanedLocalState();
            $remoteCleanup = $state ? $this->cleanupRemote($state) : $this->cleanupOrphanedRemoteState();
            return $localCleanup && $remoteCleanup ? Command::SUCCESS : Command::FAILURE;
        }
        $state = $this->readState();
        if (!$state) {
            $localCleanup = $this->cleanupOrphanedLocalState();
            $remoteCleanup = $this->cleanupOrphanedRemoteState();
            return $localCleanup && $remoteCleanup ? Command::SUCCESS : Command::FAILURE;
        }
        $remaining = (int)($state['expires_at'] ?? 0) - time();
        if ($remaining <= 0) {
            $this->cleanupLocal($state);
            $this->cleanupRemote($state);
            $this->audit('expired', $state, ['path' => 'boot-reconcile']);
            return Command::SUCCESS;
        }
        $wireguard = new WireGuardAgent();
        if (!$wireguard->reconcile($state)) {
            $this->cleanupLocal($state);
            $this->cleanupRemote($state);
            $this->audit('revoked', $state, ['reason' => 'boot-wireguard-reconcile-failed']);
            return Command::FAILURE;
        }
        $adapter = new SupportAdapter();
        if (!$adapter->reconcile($state)) {
            $this->cleanupLocal($state);
            $this->cleanupRemote($state);
            $this->audit('revoked', $state, ['reason' => 'boot-adapter-reconcile-failed']);
            return Command::FAILURE;
        }
        $attestor = new LocalAttestor();
        $attState = $attestor->state();
        if (!$attState || !hash_equals((string)($attState['session_id'] ?? ''), (string)($state['session_id'] ?? ''))) {
            if (!$attestor->placeholder($state)) {
                $this->cleanupLocal($state);
                $this->cleanupRemote($state);
                $this->audit('revoked', $state, ['reason' => 'boot-attestation-reconcile-failed']);
                return Command::FAILURE;
            }
        }
        if (!$this->scheduleExpirySeconds($state, $remaining + 1)) {
            // Fail closed: a grant that cannot be independently expired must not survive boot.
            $this->cleanupLocal($state);
            $this->cleanupRemote($state);
            $this->audit('revoked', $state, ['reason' => 'boot-expiry-scheduler-failed']);
            return Command::FAILURE;
        }
        $this->audit('reconciled', $state, ['remaining_seconds' => $remaining]);
        return Command::SUCCESS;
    }

    private function isTeliphonesEnabled(): bool
    {
        return !is_file(self::DISABLED_FILE);
    }

    private function readState(): ?array
    {
        if (!is_readable(self::STATE_FILE)) return null;
        $state = json_decode((string)file_get_contents(self::STATE_FILE), true);
        return is_array($state) ? $state : null;
    }

    private function expireIfNeeded(): void
    {
        $state = $this->readState();
        if (!$state) return;
        if (time() >= (int)($state['expires_at'] ?? 0)) {
            $this->cleanupLocal($state);
            $this->cleanupRemote($state);
            $this->audit('expired', $state, ['path' => 'opportunistic']);
        }
    }

    private function cleanupLocal(array $state): bool
    {
        $ok = true;
        foreach ([new SupportAdapter(), new WireGuardAgent(), new LocalAttestor(), new CheckerEvidence()] as $component) {
            if (!$component->destroy()) $ok = false;
        }
        if (is_file(self::STATE_FILE) && !@unlink(self::STATE_FILE)) $ok = false;
        if (!$ok) $this->writeQuarantine($state, 'local-cleanup-failed');
        return $ok;
    }

    private function cleanupOrphanedLocalState(): bool
    {
        $ok = true;
        foreach ([new SupportAdapter(), new WireGuardAgent(), new LocalAttestor(), new CheckerEvidence()] as $component) {
            if (!$component->destroy()) $ok = false;
        }
        if (!$ok) $this->writeQuarantine([], 'orphaned-local-cleanup-failed');
        return $ok;
    }

    private function writeQuarantine(array $state, string $reason): void
    {
        $record = [
            'time' => date(DATE_RFC3339),
            'session_id' => $state['session_id'] ?? null,
            'reason' => $reason,
        ];
        $temporary = self::QUARANTINE_FILE . '.tmp.' . getmypid();
        if (file_put_contents($temporary, json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX) !== false) {
            @chmod($temporary, 0600);
            if (!@rename($temporary, self::QUARANTINE_FILE)) @unlink($temporary);
        }
    }

    private function cleanupRemote(array $state): bool
    {
        $connect = new ConnectClient();
        $remote = $connect->state();
        if (!$remote) return true;
        if (!hash_equals((string)($state['session_id'] ?? ''), (string)($remote['session_id'] ?? ''))) {
            $this->writeQuarantine($state, 'gateway-session-mismatch');
            return false;
        }
        $clean = $connect->destroy($state);
        if (!$clean) $this->writeQuarantine($state, 'gateway-cleanup-failed');
        return $clean;
    }

    private function cleanupOrphanedRemoteState(): bool
    {
        $connect = new ConnectClient();
        $remote = $connect->state();
        if (!$remote) return true;
        $clean = $connect->destroy($remote);
        if (!$clean) $this->writeQuarantine($remote, 'orphaned-gateway-cleanup-failed');
        return $clean;
    }

    private function scheduleExpiry(array $state, int $minutes): bool
    {
        return $this->scheduleExpirySeconds($state, ($minutes * 60) + 1);
    }

    private function scheduleExpirySeconds(array $state, int $delay): bool
    {
        if (!$this->hasSystemdRun()) return false;
        $session = (string)$state['session_id'];
        $unit = 'teliphones-expire-' . substr($session, 0, 12) . '-' . time();
        $cmd = sprintf(
            '/usr/bin/systemd-run --quiet --unit=%s --on-active=%ds /usr/sbin/fwconsole teliphones expire --session=%s',
            escapeshellarg($unit), $delay, escapeshellarg($session)
        );
        exec($cmd . ' 2>/dev/null', $discard, $rc);
        return $rc === 0;
    }

    private function hasSystemdRun(): bool
    {
        return is_executable('/usr/bin/systemd-run') && is_executable('/usr/sbin/fwconsole');
    }

    private function writeState(array $state): bool
    {
        $tmp = self::STATE_FILE . '.tmp.' . getmypid();
        $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        if (file_put_contents($tmp, $json, LOCK_EX) === false) return false;
        @chmod($tmp, 0600);
        if (!rename($tmp, self::STATE_FILE)) { @unlink($tmp); return false; }
        return true;
    }

    private function auditSimple(string $event, array $extra = []): void
    {
        $entry = array_merge(['time' => date(DATE_RFC3339), 'event' => $event], $extra);
        @file_put_contents(self::AUDIT_FILE, json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
        @chmod(self::AUDIT_FILE, 0600);
    }

    private function audit(string $event, array $state, array $extra = []): void
    {
        $entry = array_merge([
            'time' => date(DATE_RFC3339),
            'event' => $event,
            'session_id' => $state['session_id'] ?? null,
            'transport' => $state['transport'] ?? null,
            'expires_at' => $state['expires_at'] ?? null,
        ], $extra);
        @file_put_contents(self::AUDIT_FILE, json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
        @chmod(self::AUDIT_FILE, 0600);
    }
}
