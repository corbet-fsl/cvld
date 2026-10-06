# Native headers and build tools for Linux verification.
# Lock-evidenced (Cargo.lock): openssl-sys linked via the webauthn stack
# (openssl crate), cmake edges via aws-lc-sys (rustls/reqwest/quinn),
# libsql-ffi and wasmer; pkg-config discovery for openssl-sys; cc via the
# shell stdenv (Ubuntu-image gcc equivalent). libclang is deliberately
# absent: bindgen edges in the lock are optional (libsql-ffi "bindgen"
# feature off, wasmer prebuilt path) and Ubuntu CI — which this job mirrors
# — ships no libclang. cc/cmake are worker-provided through this shell, not
# the base image. Both checks execute inside this shell (see run-cached.sh).
{ pkgs ? import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436.tar.gz";
  sha256 = "sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=";
}) {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    openssl
  ];
  nativeBuildInputs = with pkgs; [
    pkg-config
    cmake
  ];
  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl ]}:''${LD_LIBRARY_PATH:-}";
  '';
}
