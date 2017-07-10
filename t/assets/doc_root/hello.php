<?php
if (isset($_GET['link'])) {
    header('Link: ' . $_GET['link']);
}
echo "hello world";
?>
