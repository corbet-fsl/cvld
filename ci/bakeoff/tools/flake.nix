{
  description = "Round 2 shared Rust CI toolchain (identical for every variant and repository)";
  inputs.nixpkgs.url = "https://api.flakehub.com/f/pinned/DeterminateSystems/nixpkgs-weekly/0.1.1077143%2Brev-44a91898084f46797b5fac650c7e8c9ac38c43d4/01a0ebad-51ce-7451-8dd8-3e80d608beae/source.tar.gz";
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      toolchain = pkgs.symlinkJoin {
        name = "bakeoff-rust-toolchain";
        paths = with pkgs; [ rustc cargo clippy rustfmt ];
      };
      native = with pkgs; [ pkg-config openssl.dev openssl.out pam python3 cmake ];
      cli = with pkgs; [ toolchain stdenv.cc bash coreutils findutils gnugrep gnused gnutar gzip time dbus cacert git mold sccache ];
      environment = pkgs.writeShellScriptBin "bakeoff-env" ''
        export PATH=${pkgs.lib.makeBinPath (cli ++ native)}
        export OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib
        export OPENSSL_INCLUDE_DIR=${pkgs.openssl.dev}/include
        export LIBRARY_PATH=${pkgs.pam}/lib:${pkgs.openssl.out}/lib
        export LD_LIBRARY_PATH=${pkgs.pam}/lib:${pkgs.openssl.out}/lib
        export PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig
        export NIX_LDFLAGS="-L${pkgs.pam}/lib -rpath ${pkgs.pam}/lib -L${pkgs.openssl.out}/lib -rpath ${pkgs.openssl.out}/lib"
        export PYO3_PYTHON=${pkgs.python3}/bin/python3
        export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
        export CARGO_BUILD_JOBS=''${CARGO_BUILD_JOBS:-16} RUST_TEST_THREADS=''${RUST_TEST_THREADS:-16} CARGO_TERM_COLOR=never
        exec "$@"
      '';
      tools = pkgs.buildEnv { name = "bakeoff-tools"; paths = [ environment ] ++ cli ++ native; ignoreCollisions = true; };
    in {
      packages.${system} = {
        inherit tools;
        image = pkgs.dockerTools.buildImage {
          name = "bakeoff-rust";
          tag = "toolchain2";
          copyToRoot = pkgs.buildEnv { name = "bakeoff-image-root"; paths = [ tools pkgs.dockerTools.binSh ]; pathsToLink = [ "/bin" "/etc" ]; };
          config = { Env = [ "PATH=/bin" "HOME=/home/build" ]; WorkingDir = "/src"; };
        };
      };
    };
}
