{pkgs}: {
  deps = [
    pkgs.curl
    pkgs.wget
    pkgs.cacert
    pkgs.postgresql
    pkgs.openssl
  ];
}
