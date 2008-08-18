#!/bin/sh
VERSION=0.1.0

rm *.gem *.tar.bz2
rm -rf doc
rdoc README.txt ext/aesruby.c --title 'AES/Ruby - Ruby bindings for C implementation of AES.'
tar jcvf aesruby-${VERSION}.tar.bz2 --exclude=.svn README.txt *.gemspec ext doc
gem build aesruby.gemspec
