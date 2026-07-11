rule WebShellDetect {
  meta:
    description = "Detect simple PHP webshell pattern"
  strings:
    $eval = "eval"
    $get = "$_GET"
  condition:
    $eval and $get
}
