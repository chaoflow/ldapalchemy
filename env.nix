let
  pkgs = import ./nixpkgs {};
  siteFor = python:
    python.site {
      name = "ldapalchemy-dev";
      wheels = with python.wheels;
        [ cffi
          ipdb
          plumbum
          py
          pytest
          pytest-cache
          pytest-pep8
          pytest-flakes
          setuptools
          virtualenv

          # pas.plugins.ldapalchemy
          zc_buildout_v1_7
        ];
      scriptsFor = with python.wheels; [ ipdb pytest virtualenv zc_buildout_v1_7 ];
      postBuild = "install $out/bin/virtualenv $out/bin/virtualenv${python.majorVersion}";
    };

in
pkgs.buildEnv {
  name = "ldapalchemy-dev";
  paths =
    [ (pkgs.misc.debugVersion pkgs.openldap)  # for tests
      pkgs.flake8
      pkgs.gdb                                # for debugging
      pkgs.openssl                            # to create self-signed cert
    ] ++ (map siteFor (with pkgs; [ python27 ]));
  ignoreCollisions = true;
}