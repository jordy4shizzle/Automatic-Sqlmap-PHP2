<?php
ini_set('display_startup_errors',1);
ini_set('display_errors',1);
error_reporting(-1);

$mysql = mysql_connect("192.168.2.17","root","a59d6b8ffa4519019833533686");
if (!$mysql) {
    die('Could not connect: ' . mysql_error());
}

$dump = false;

$id = $_GET['id'];

if(isset($_GET['dump']))
{
    $dump = true;
}

mysql_select_db("SQLMAP");

$res = mysql_query("SELECT id FROM Website WHERE id=$id");

if(!$res)
{
    exit(mysql_error());
}
while($data = mysql_fetch_assoc($res)){
    $id = $data['id'];
    echo "ID: ".$id;
}
//
//$client = $_SERVER['REMOTE_ADDR'];
//$x = mysql_query("INSERT INTO remote VALUES(0, '$client')");
//if(!$x)
//{
//    exit("NEIN!");
//}
//
//if($dump)
//{
//    $result2 = mysql_query("SELECT * FROM remote");
//
//    while($data2 = mysql_fetch_assoc($result2))
//    {
//       echo("ROW: <pre>".print_r($data2, true)."</pre><br/ ><br />");
//    }
//}