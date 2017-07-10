<?php
if (isset($_GET['link'])) {
    //header('Link: ' . $_GET['link']);
    header('Link: <index.js>; rel=preload');
}
echo "hello world";
?>
