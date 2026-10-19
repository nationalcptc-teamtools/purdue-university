DELETE FROM hostnames WHERE name = 'SSL_Self_Signed_Fallback' OR instr(name, '\x00') > 0;
