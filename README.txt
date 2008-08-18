= AES/Ruby

== Description

Ruby bindings for C implementation of AES.

== Example

    require 'aesruby'
    
    enc = AES.ecb_encrypt("123456", "dd")
    p enc
    puts AES.ecb_decrypt("123456", enc);
    
    enc = AES.cbc_encrypt("123456", "dd")
    p enc
    puts AES.cbc_decrypt("123456", enc);

== implementation of AES

* Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.
* see http://fp.gladman.plus.com/AES/
