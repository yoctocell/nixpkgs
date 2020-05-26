{ lib, pkgs, config, ... }:

with lib;

let
  cfg = config.services.public-inbox;
  stateDir = "/var/lib/public-inbox";

  manref = name: vol: "<citerefentry><refentrytitle>${name}</refentrytitle><manvolnum>${toString vol}</manvolnum></citerefentry>";

  singleIniAtom = with types; nullOr (oneOf [ bool int float str ]) // {
    description = "INI atom (null, bool, int, float or string)";
  };
  iniAtom = with types; coercedTo singleIniAtom singleton (listOf singleIniAtom) // {
    description = singleIniAtom.description + " or a list of them for duplicate keys";
  };
  iniAttrs = with types; attrsOf (either (attrsOf iniAtom) iniAtom);
  gitIni = {
    type = with types; attrsOf iniAttrs;
    generate = name: value: pkgs.writeText name (generators.toGitINI value);
  };

  environment = {
    PI_EMERGENCY = "${stateDir}/emergency";
    PI_CONFIG = gitIni.generate "public-inbox.ini"
      (filterAttrsRecursive (n: v: v != null) cfg.settings);
  };

  useSpamAssassin = cfg.settings.publicinboxmda.spamcheck == "spamc" ||
                    cfg.settings.publicinboxwatch.spamcheck == "spamc";

  serviceConfig = srv: {
    # Enable JIT-compiled C (via Inline::C)
    Environment = [ "PERL_INLINE_DIRECTORY=/run/public-inbox-${srv}/perl-inline" ];
    # NonBlocking is REQUIRED to avoid a race condition
    # if running simultaneous services.
    NonBlocking = true;
    #LimitNOFILE = 30000;
    User = config.users.users."public-inbox".name;
    Group = config.users.groups."public-inbox".name;
    RuntimeDirectory = [
      "public-inbox-${srv}/perl-inline"
      # Create RootDirectory= in the host's mount namespace.
      "public-inbox-${srv}/root"
    ];
    RuntimeDirectoryMode = "700";
    # Avoid mounting RootDirectory= in the own RootDirectory= of ExecStart='s mount namespace.
    InaccessiblePaths = ["-+/run/public-inbox-${srv}/root"];
    # This is for BindPaths= and BindReadOnlyPaths=
    # to allow traversal of directories they create in RootDirectory=.
    UMask = "0066";
    RootDirectory = "/run/public-inbox-${srv}/root";
    RootDirectoryStartOnly = true;
    WorkingDirectory = stateDir;
    MountAPIVFS = true;
    BindReadOnlyPaths = [
      builtins.storeDir
      "/etc"
      "/run"
    ];
    BindPaths = [
      stateDir
    ];
    # The following options are only for optimizing:
    # systemd-analyze security public-inbox-'*'
    AmbientCapabilities = "";
    CapabilityBoundingSet = "";
    # ProtectClock= adds DeviceAllow=char-rtc r
    DeviceAllow = "";
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    NoNewPrivileges = true;
    PrivateDevices = true;
    PrivateMounts = true;
    PrivateNetwork = mkDefault false;
    PrivateTmp = true;
    PrivateUsers = true;
    ProtectClock = true;
    ProtectControlGroups = true;
    ProtectHome = true;
    ProtectHostname = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectSystem = "strict";
    RemoveIPC = true;
    RestrictAddressFamilies = [ "AF_UNIX" ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallFilter = [
      "@system-service"
      "~@aio" "~@chown" "~@ipc" "~@keyring" "~@memlock"
      "~@resources" "~@setuid" "~@timer" "~@privileged"
    ];
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
  };
in

{
  options.services.public-inbox = {
    enable = mkEnableOption "the public-inbox mail archiver";
    package = mkOption {
      type = types.package;
      default = pkgs.public-inbox;
      description = "public-inbox package to use.";
    };
    path = mkOption {
      type = with types; listOf package;
      default = [];
      example = literalExample "with pkgs; [ spamassassin ]";
      description = ''
        Additional packages to place in the path of public-inbox-mda,
        public-inbox-watch, etc.
      '';
    };
    inboxes = mkOption {
      description = ''
        Inboxes to configure, where attribute names are inbox names.
      '';
      default = {};
      type = types.submodule {
        freeformType = types.attrsOf (types.submodule ({name, ...}: {
          freeformType = types.attrsOf iniAtom;
          options.inboxdir = mkOption {
            type = types.str;
            default = "${stateDir}/inboxes/${name}";
            description = "The absolute path to the directory which hosts the public-inbox.";
          };
          options.address = mkOption {
            type = with types; listOf str;
            example = "example-discuss@example.org";
            description = "The email addresses of the public-inbox.";
          };
          options.url = mkOption {
            type = with types; nullOr str;
            default = null;
            example = "https://example.org/lists/example-discuss";
            description = "URL where this inbox can be accessed over HTTP.";
          };
          options.description = mkOption {
            type = types.str;
            example = "user/dev discussion of public-inbox itself";
            description = "User-visible description for the repository.";
          };
          options.newsgroup = mkOption {
            type = with types; nullOr str;
            default = null;
            description = "NNTP group name for the inbox.";
          };
          options.watch = mkOption {
            type = with types; listOf str;
            default = [];
            description = "Paths for ${manref "public-inbox-watch" 1} to monitor for new mail.";
            example = [ "maildir:/path/to/test.example.com.git" ];
          };
          options.watchheader = mkOption {
            type = with types; nullOr str;
            default = null;
            example = "List-Id:<test@example.com>";
            description = ''
              If specified, ${manref "public-inbox-watch" 1} will only process
              mail containing a matching header.
            '';
          };
          options.coderepo = mkOption {
            type = (types.listOf (types.enum (attrNames cfg.settings.coderepo))) // {
              description = "list of coderepo names";
            };
            default = [];
            description = "Nicknames of a 'coderepo' section associated with the inbox.";
          };
        }));
      };
    };
    mda = {
      enable = mkEnableOption "the public-inbox Mail Delivery Agent";
      args = mkOption {
        type = with types; listOf str;
        default = [];
        description = "Command-line arguments to pass to ${manref "public-inbox-mda" 1}.";
      };
    };
    http = {
      enable = mkEnableOption "the public-inbox HTTP server";
      mounts = mkOption {
        type = with types; listOf str;
        default = [ "/" ];
        example = [ "/lists/archives" ];
        description = ''
          Root paths or URLs that public-inbox will be served on.
          If domain parts are present, only requests to those
          domains will be accepted.
        '';
      };
      args = mkOption {
        type = with types; listOf str;
        default = ["-W0"];
        description = "Command-line arguments to pass to ${manref "public-inbox-httpd" 1}.";
      };
      port = mkOption {
        type = with types; nullOr (either str port);
        default = 80;
        example = "/run/public-inbox-httpd.sock";
        description = ''
          Listening port or systemd's ListenStream= entry
          to be used as a reverse proxy, eg. in nginx:
          <code>locations."/inbox".proxyPass = "http://unix:''${config.services.public-inbox.http.port}:/inbox";</code>
          Set to null and use <code>systemd.sockets.public-inbox-httpd.listenStreams</code>
          if you need a more advanced listening.
        '';
      };
    };
    imap = {
      enable = mkEnableOption "the public-inbox IMAP server";
      args = mkOption {
        type = with types; listOf str;
        default = ["-W0"];
        description = "Command-line arguments to pass to ${manref "public-inbox-imapd" 1}.";
      };
      port = mkOption {
        type = with types; nullOr port;
        default = 993;
        description = ''
          Listening port.
          Set to null and use <code>systemd.sockets.public-inbox-imapd.listenStreams</code>
          if you need a more advanced listening.
        '';
      };
      cert = mkOption {
        type = with types; nullOr str;
        default = null;
        example = "/path/to/fullchain.pem";
        description = "Path to TLS certificate to use for public-inbox IMAP connections.";
      };
      key = mkOption {
        type = with types; nullOr str;
        default = null;
        example = "/path/to/key.pem";
        description = "Path to TLS key to use for public-inbox IMAP connections.";
      };
    };
    nntp = {
      enable = mkEnableOption "the public-inbox NNTP server";
      port = mkOption {
        type = with types; nullOr port;
        default = 563;
        description = ''
          Listening port.
          Set to null and use <code>systemd.sockets.public-inbox-nntpd.listenStreams</code>
          if you need a more advanced listening.
        '';
      };
      args = mkOption {
        type = with types; listOf str;
        default = ["-W0"];
        description = "Command-line arguments to pass to ${manref "public-inbox-nntpd" 1}.";
      };
      cert = mkOption {
        type = with types; nullOr str;
        default = null;
        example = "/path/to/fullchain.pem";
        description = "Path to TLS certificate to use for public-inbox NNTP connections";
      };
      key = mkOption {
        type = with types; nullOr str;
        default = null;
        example = "/path/to/key.pem";
        description = "Path to TLS key to use for public-inbox NNTP connections.";
      };
    };
    spamAssassinRules = mkOption {
      type = with types; nullOr path;
      default = "${cfg.package.sa_config}/user/.spamassassin/user_prefs";
      description = "SpamAssassin configuration specific to public-inbox.";
    };
    settings = mkOption {
      description = "Settings for the public-inbox config file.";
      default = {};
      type = types.submodule {
        freeformType = gitIni.type;
        options.publicinbox = mkOption {
          default = {};
          description = "public-inbox configuration.";
          type = types.submodule {
            freeformType = iniAttrs;
            options.css = mkOption {
              type = with types; listOf str;
              default = [];
              description = "The local path name of a CSS file for the PSGI web interface.";
            };
            options.nntpserver = mkOption {
              type = with types; listOf str;
              default = [];
              example = [ "nntp://news.public-inbox.org" "nntps://news.public-inbox.org" ];
              description = "NNTP URLs to this public-inbox instance";
            };
            options.wwwlisting = mkOption {
              type = with types; enum [ "all" "404" "match=domain" ];
              default = "404";
              description = ''
                Controls which lists (if any) are listed for when the root
                public-inbox URL is accessed over HTTP.
              '';
            };
          };
        };
        options.publicinboxmda = mkOption {
          default = {};
          description = "mailbox delivery agent";
          type = types.submodule {
            freeformType = iniAttrs;
            options.spamcheck = mkOption {
              type = with types; enum [ "spamc" "none" ];
              default = "none";
              description = ''
                If set to spamc, ${manref "public-inbox-watch" 1} will filter spam
                using SpamAssassin.
              '';
            };
          };
        };
        options.publicinboxwatch = mkOption {
          default = {};
          description = "mailbox watcher";
          type = types.submodule {
            freeformType = iniAttrs;
            options.spamcheck = mkOption {
              type = with types; enum [ "spamc" "none" ];
              default = "none";
              description = ''
                If set to spamc, ${manref "public-inbox-watch" 1} will filter spam
                using SpamAssassin.
              '';
            };
            options.watchspam = mkOption {
              type = with types; nullOr str;
              default = null;
              example = "maildir:/path/to/spam";
              description = ''
                If set, mail in this maildir will be trained as spam and
                deleted from all watched inboxes
              '';
            };
          };
        };
        options.coderepo = mkOption {
          default = {};
          description = "code repositories";
          type = types.submodule {
            freeformType = types.attrsOf (types.submodule {
              freeformType = types.either (types.attrsOf iniAtom) iniAtom;
              options.cgitUrl = mkOption {
                type = types.str;
                description = "URL of a cgit instance";
              };
              options.dir = mkOption {
                type = types.str;
                description = "Path to a git repository";
              };
            });
          };
        };
      };
    };
    openFirewall = mkEnableOption "opening the firewall when using a port option";
  };
  config = mkIf cfg.enable {
    assertions = [
      { assertion = config.services.spamassassin.enable || !useSpamAssassin;
        message = ''
          public-inbox is configured to use SpamAssassin, but
          services.spamassassin.enable is false.  If you don't need
          spam checking, set `services.public-inbox.settings.publicinboxmda.spamcheck' and
          `services.public-inbox.settings.publicinboxwatch.spamcheck' to null.
        '';
      }
      { assertion = cfg.path != [] || !useSpamAssassin;
        message = ''
          public-inbox is configured to use SpamAssassin, but there is
          no spamc executable in services.public-inbox.path.  If you
          don't need spam checking, set
          `services.public-inbox.settings.publicinboxmda.spamcheck' and
          `services.public-inbox.settings.publicinboxwatch.spamcheck' to null.
        '';
      }
    ];
    services.public-inbox.settings =
      filterAttrsRecursive (n: v: v != null) {
      publicinbox = mapAttrs (n: filterAttrs (n: v: n != "description")) cfg.inboxes;
    };
    users = {
      users.public-inbox = {
        # Use runCommand instead of linkFarm,
        # because Postfix rejects .forward if it's a symlink.
        home = pkgs.runCommand "public-inbox-home" {} (''
          install -D -p ${environment.PI_CONFIG} $out/.public-inbox/config
          ln -s ${stateDir}/emergency $out/.public-inbox/emergency
          ln -s ${stateDir}/spamassassin $out/.spamassassin
        '' + optionalString cfg.mda.enable ''
          cp ${let env = concatStringsSep " " (mapAttrsToList (n: v: "${n}=${escapeShellArg v}") environment); in
            pkgs.writeText "forward" ''
              |"env ${env} PATH=\"${makeBinPath cfg.path}:$PATH\" ${cfg.package}/bin/public-inbox-mda ${escapeShellArgs cfg.mda.args}
          ''} $out/.forward
        '');
        group = "public-inbox";
        isSystemUser = true;
      };
      groups.public-inbox = {};
    };
    networking.firewall = mkIf cfg.openFirewall
      { allowedTCPPorts = mkMerge [
          (mkIf (cfg.http.enable && types.port.check cfg.http.port) [ cfg.http.port ])
          (mkIf (cfg.imap.enable && types.port.check cfg.imap.port) [ cfg.imap.port ])
          (mkIf (cfg.nntp.enable && types.port.check cfg.nntp.port) [ cfg.nntp.port ])
        ];
      };
    systemd.sockets = mkMerge (map (proto:
      mkIf (cfg.${proto}.enable && cfg.${proto}.port != null)
        { "public-inbox-${proto}d" = {
            listenStreams = [ (toString cfg.${proto}.port) ];
            wantedBy = [ "sockets.target" ];
          };
        }
      ) [ "http" "imap" "nntp" ]);
    systemd.services = mkMerge [
      (mkIf cfg.http.enable
        { public-inbox-httpd = {
          inherit environment;
          after = [ "public-inbox-init.service" "public-inbox-watch.service" ];
          requires = [ "public-inbox-init.service" ];
          serviceConfig = serviceConfig "httpd" // {
            ExecStart = escapeShellArgs (
              [ "${cfg.package}/bin/public-inbox-httpd" ] ++
              cfg.http.args ++
              [ (pkgs.writeText "public-inbox.psgi" ''
                #!${cfg.package.fullperl} -w
                use strict;
                use PublicInbox::WWW;
                use Plack::Builder;

                my $www = PublicInbox::WWW->new;
                $www->preload;

                builder {
                  enable 'Head';
                  enable 'ReverseProxy';
                  ${concatMapStrings (path: ''
                  mount q(${path}) => sub { $www->call(@_); };
                  '') cfg.http.mounts}
                }
              '') ]
            );
          };
        };
      })
      (mkIf cfg.imap.enable
        { public-inbox-imapd = {
          inherit environment;
          after = [ "public-inbox-init.service" "public-inbox-watch.service" ];
          requires = [ "public-inbox-init.service" ];
          serviceConfig = serviceConfig "imapd" // {
            ExecStart = escapeShellArgs (
              [ "${cfg.package}/bin/public-inbox-imapd" ] ++
              cfg.imap.args ++
              optionals (cfg.imap.cert != null) [ "--cert" cfg.imap.cert ] ++
              optionals (cfg.imap.key != null) [ "--key" cfg.imap.key ]
            );
          };
        };
      })
      (mkIf cfg.nntp.enable
        { public-inbox-nntpd = {
          inherit environment;
          after = [ "public-inbox-init.service" "public-inbox-watch.service" ];
          requires = [ "public-inbox-init.service" ];
          serviceConfig = serviceConfig "nntpd" // {
            ExecStart = escapeShellArgs (
              [ "${cfg.package}/bin/public-inbox-nntpd" ] ++
              cfg.nntp.args ++
              optionals (cfg.nntp.cert != null) [ "--cert" cfg.nntp.cert ] ++
              optionals (cfg.nntp.key != null) [ "--key" cfg.nntp.key ]
            );
          };
        };
      })
      (mkIf (any (inbox: inbox.watch != []) (attrValues cfg.inboxes)
        || cfg.settings.publicinboxwatch.watchspam != null)
        { public-inbox-watch = {
          inherit environment;
          inherit (cfg) path;
          wants = [ "public-inbox-init.service" ];
          requires = [ "public-inbox-init.service" ] ++
            optional (cfg.settings.publicinboxwatch.spamcheck == "spamc") "spamassassin.service";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = serviceConfig "watch" // {
            ExecStart = "${cfg.package}/bin/public-inbox-watch";
            ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
          };
        };
      })
      ({ public-inbox-init = {
          inherit environment;
          wantedBy = [ "multi-user.target" ];
          restartIfChanged = true;
          restartTriggers = [ environment.PI_CONFIG ];
          script = ''
            set -ux
            ${optionalString useSpamAssassin ''
              install -m 0700 -o spamd -d ${stateDir}/spamassassin
              ${optionalString (cfg.spamAssassinRules != null) ''
                ln -sf ${cfg.spamAssassinRules} ${stateDir}/spamassassin/user_prefs
              ''}
            ''}

            ${concatStrings (mapAttrsToList (name: inbox: ''
              if [ ! -e ${stateDir}/inboxes/${escapeShellArg name} ]; then
                # public-inbox-init creates an inbox and adds it to a config file.
                # It tries to atomically write the config file by creating
                # another file in the same directory, and renaming it.
                # This has the sad consequence that we can't use
                # /dev/null, or it would try to create a file in /dev.
                conf_dir="$(${pkgs.sudo}/bin/sudo mktemp -d)"

                ${pkgs.sudo}/bin/sudo \
                  env PI_CONFIG=$conf_dir/conf \
                  ${cfg.package}/bin/public-inbox-init -V2 \
                  ${escapeShellArgs ([ name "${stateDir}/inboxes/${name}" inbox.url ] ++ inbox.address)}

                rm -rf $conf_dir
              fi

              ${pkgs.sudo}/bin/sudo ln -sf ${pkgs.writeText "description" inbox.description} \
                ${stateDir}/inboxes/${escapeShellArg name}/description

              export GIT_DIR=${stateDir}/inboxes/${escapeShellArg name}/all.git
              if test -d "$GIT_DIR"; then
                # Config is inherited by each epoch repository,
                # so just needs to be set for all.git.
                ${pkgs.git}/bin/git config core.sharedRepository 0640
              fi
            '') cfg.inboxes)}

            for inbox in ${stateDir}/inboxes/*/; do
              ls -1 "$inbox" | grep -q '^xap' && continue

              # This should be idempotent, but only do it for new
              # inboxes anyway because it's only needed once, and could
              # be slow for large pre-existing inboxes.
              ${pkgs.sudo}/bin/sudo -u public-inbox \
              ${cfg.package}/bin/public-inbox-index "$inbox"
            done
          '';
          serviceConfig = serviceConfig "init" // {
            Type = "oneshot";
            RemainAfterExit = true;
            StateDirectory = [
              "public-inbox"
              "public-inbox/emergency"
              "public-inbox/inboxes"
            ];
            StateDirectoryMode = "0750";
          };
        };
      })
    ];
    environment.systemPackages = with pkgs; [ cfg.package ];
  };
  meta.maintainers = with lib.maintainers; [ julm ];
}
