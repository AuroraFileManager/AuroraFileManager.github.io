<?php

const APP_NAME = 'AuroraFile';
const SCAN_READ_LIMIT = 200_000; 

const MALWARE_SIGS = [

  '/(?i)(eval|assert|exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(/',

  '/(?i)(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|pack|unserialize)\s*\(/',

  '/(?i)(b374k|c99shell|r57shell|wso|webshell|cmdshell|phpremoteview|cp\.\s*php)/',

  '/(?i)preg_replace\s*\(.*?\/e.*?\)/',

  '/(?i)(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST|SERVER)\[/',

  '/\$\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*/',

  '/\$_(GET|POST|COOKIE|REQUEST|SERVER|FILES)\s*\[/'
];

function fmtSize(int $b): string {
  return match(true){
    $b >= 1<<30 => sprintf('%.2f GB',$b/(1<<30)),
    $b >= 1<<20 => sprintf('%.2f MB',$b/(1<<20)),
    $b >= 1<<10 => sprintf('%.2f KB',$b/1024),
    default     => $b.' B',
  };
}
function ext(string $f): string { return strtolower(pathinfo($f, PATHINFO_EXTENSION)); }
function icon(string $f): string {
  static $img=['png','jpg','jpeg','gif','svg','webp','apng','avif'];
  static $aud=['mp3','ogg','wav','m4a'];
  $e = ext($f);
  return match(true){
    $f==='error_log'             => '<i class="fa-solid fa-bug text-danger"></i>',
    $f==='.htaccess'             => '<i class="fa-solid fa-hammer text-warning"></i>',
    in_array($e,['html','htm'])  => '<i class="fa-brands fa-html5 text-danger"></i>',
    in_array($e,['php','phtml']) => '<i class="fa-brands fa-php text-indigo"></i>',
    in_array($e,$img)            => '<i class="fa-regular fa-image text-success"></i>',
    $e==='css'                   => '<i class="fa-brands fa-css3 text-primary"></i>',
    $e==='txt'                   => '<i class="fa-regular fa-file-lines text-secondary"></i>',
    in_array($e,$aud)            => '<i class="fa-solid fa-music text-primary"></i>',
    $e==='js'                    => '<i class="fa-brands fa-js text-warning"></i>',
    $e==='py'                    => '<i class="fa-brands fa-python text-warning"></i>',
    default                      => '<i class="fa-solid fa-file text-muted"></i>',
  };
}
function enc(string $p): string {return str_replace(['/', '\\', '.'], ['ক','খ','গ'],$p);}  
function dec(string $p): string {return str_replace(['ক','খ','গ'], ['/', '\\', '.'],$p);}  
function perms(string $p): string {return substr(sprintf('%o', fileperms($p)),-3);}  

function malwareScan(string $dir): array {
  $hits = [];
  $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));

  foreach($it as $f){
    if(!$f->isFile()) continue;

    $ext = strtolower($f->getExtension());
    if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp', 'zip'])) continue; 

    $size = $f->getSize();
    if($size === 0) continue;

    $path = $f->getPathname();
    $handle = @fopen($path, 'r');
    if(!$handle) continue;

    $content = fread($handle, SCAN_READ_LIMIT);
    fclose($handle);

    foreach(MALWARE_SIGS as $sig){
      if(preg_match($sig, $content)){
        $hits[] = [
          'file'  => $path,
          'sig'   => trim($sig, '/'),
          'size'  => $size
        ];
        break; 
      }
    }

    if (preg_match('/base64_decode\s*\(\s*[\'"]([A-Za-z0-9\/+=]+)[\'"]\s*\)/i', $content, $matches)) {
      $decoded = base64_decode($matches[1]);
      foreach(MALWARE_SIGS as $sig){
        if(preg_match($sig, $decoded)){
          $hits[] = [
            'file'  => $path . ' (base64 decoded)',
            'sig'   => 'Decoded: ' . trim($sig, '/'),
            'size'  => $size
          ];
          break;
        }
      }
    }

    if (substr_count($content, "\n") < 5 && strlen($content) > 1000) {
      $hits[] = [
        'file' => $path,
        'sig'  => 'Obfuscated (few newlines)',
        'size' => $size
      ];
    }
  }
  return $hits;
}

$root   = realpath(__DIR__);
$req    = $_GET['p']??'';
$path   = $root;
if($req!==''){
  $tmp=dec($req);
  if(is_dir($tmp)) $path=$tmp; else {echo"<script>alert('Bad dir');location='?p=';</script>";exit;}
}

define('PATH',$path);
$act    = $_GET['act']??'list'; 
$target = $_GET['file']??'';

if(isset($_POST['upload'])){
  $dest = PATH.'/'.basename($_FILES['file']['name']);
  move_uploaded_file($_FILES['file']['tmp_name'],$dest);
  header('Location:?p='.enc(PATH));exit;
}
if(isset($_POST['mkfolder'])){
  @mkdir(PATH.'/'.$_POST['folder'],0755);
  header('Location:?p='.enc(PATH));exit;
}
if(isset($_POST['mkfile'])){
  $f = PATH.'/'.$_POST['filename'];
  if(!file_exists($f)) file_put_contents($f,'');
  header('Location:?p='.enc(PATH).'&act=edit&file='.urlencode($_POST['filename']));exit;
}
if(isset($_POST['rename'])){
  rename(PATH.'/'.$_POST['old'], PATH.'/'.$_POST['new']);
  header('Location:?p='.enc(PATH));exit;
}
if(isset($_POST['save'])){
  file_put_contents(PATH.'/'.$target,$_POST['data']);
  header('Location:?p='.enc(PATH));exit;
}
if(isset($_POST['chmod'])){
  chmod(PATH.'/'.$target, intval($_POST['mode'],8));
  header('Location:?p='.enc(PATH));exit;
}
if(isset($_GET['del'])){
  $f=PATH.'/'.$_GET['del'];
  is_dir($f)?rmdir($f):unlink($f);
  header('Location:?p='.enc(PATH));exit;
}

if($act==='scan'){
  $scanResults = malwareScan(PATH);
}

$dirs=$files=[]; if($act==='list'){
  foreach(scandir(PATH) as $e){ if($e==='.'||$e==='..') continue; is_dir(PATH."/$e")?$dirs[]=$e:$files[]=$e; }
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?=APP_NAME?></title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:var(--bs-body-bg);} 
    .glass{backdrop-filter:blur(20px) saturate(180%);background:rgba(255,255,255,.6)!important;}
    [data-bs-theme="dark"] .glass{background:rgba(18,18,18,.6)!important;}
    .table thead{position:sticky;top:0;backdrop-filter:blur(12px);} textarea{font-family:SFMono-Regular,Consolas,Menlo,monospace;font-size:.875rem;}
  </style>
</head>
<body class="d-flex flex-column min-vh-100">
<nav class="navbar glass shadow-sm sticky-top">
  <div class="container-fluid gap-2">
    <a class="navbar-brand d-flex align-items-center gap-2 fw-semibold" href="?p=<?=enc($root)?>"><i class="fa-solid fa-folder-tree"></i><?=APP_NAME?></a>
    <?php  $crumb=''; ?>
    <div class="d-none d-md-flex align-items-center overflow-auto me-auto">
      <ol class="breadcrumb mb-0 bg-transparent py-0">
        <li class="breadcrumb-item"><a href="?p=<?=enc($root)?>">Root</a></li>
        <?php $parts=array_filter(explode('/',str_replace('\\','/',substr(PATH,strlen($root)))));
          foreach($parts as $p){$crumb.='/'.$p; echo"<li class='breadcrumb-item'><a href='?p=".enc($root.$crumb)."'>".htmlspecialchars($p)."</a></li>";} ?>
      </ol>
    </div>
    <div class="d-flex gap-1">
      <?php if($act==='list'):?>
      <a class="btn btn-outline-primary btn-sm" href="?p=<?=enc(PATH)?>&act=upload" data-bs-toggle="tooltip" data-bs-title="Upload"><i class="fa-solid fa-upload"></i></a>
      <a class="btn btn-outline-primary btn-sm" href="?p=<?=enc(PATH)?>&act=mkfile" data-bs-toggle="tooltip" data-bs-title="New file"><i class="fa-solid fa-file-circle-plus"></i></a>
      <a class="btn btn-outline-primary btn-sm" href="?p=<?=enc(PATH)?>&act=mkdir" data-bs-toggle="tooltip" data-bs-title="New folder"><i class="fa-solid fa-folder-plus"></i></a>
      <a class="btn btn-outline-danger btn-sm" href="?p=<?=enc(PATH)?>&act=scan" data-bs-toggle="tooltip" data-bs-title="Malware scan"><i class="fa-solid fa-shield-virus"></i></a>
      <?php endif; ?>
      <button id="themeBtn" class="btn btn-outline-primary btn-sm"><i class="fa-solid fa-moon"></i></button>
    </div>
  </div>
</nav>

<!-- FILE TABLE -->
<div class="container-fluid flex-grow-1 py-4 <?php if($act!=='list') echo 'd-none'; ?>">
  <div class="table-responsive rounded-4 shadow-sm overflow-hidden">
    <table class="table table-hover align-middle mb-0">
      <thead class="glass"><tr><th style="width:38%">Name</th><th class="text-end">Size</th><th>Modified</th><th>Perms</th><th style="width:150px">Actions</th></tr></thead>
      <tbody>
        <?php foreach($dirs as $d): ?>
        <tr>
          <td><?=icon($d)?> <a href="?p=<?=enc(PATH.'/'.$d)?>" class="fw-medium text-decoration-none"><?=htmlspecialchars($d)?></a></td>
          <td class="text-end text-muted">—</td>
          <td><?=date('Y-m-d H:i',filemtime(PATH."/$d"))?></td>
          <td><span class="badge bg-secondary perms"><?=perms(PATH."/$d")?></span></td>
          <td><div class="btn-group btn-group-sm"><a class="btn btn-outline-primary" href="?p=<?=enc(PATH)?>&act=rename&file=<?=urlencode($d)?>"><i class="fa-regular fa-pen-to-square"></i></a><a class="btn btn-outline-warning" href="?p=<?=enc(PATH)?>&act=chmod&file=<?=urlencode($d)?>"><i class="fa-solid fa-key"></i></a><a class="btn btn-outline-danger" href="?p=<?=enc(PATH)?>&del=<?=urlencode($d)?>" onclick="return confirm('Delete folder?')"><i class="fa-solid fa-trash"></i></a></div></td>
        </tr>
        <?php endforeach; foreach($files as $f): ?>
        <tr>
          <td><?=icon($f)?> <?=htmlspecialchars($f)?></td>
          <td class="text-end"><?=fmtSize(filesize(PATH."/$f"))?></td>
          <td><?=date('Y-m-d H:i',filemtime(PATH."/$f"))?></td>
          <td><span class="badge bg-secondary perms"><?=perms(PATH."/$f")?></span></td>
          <td><div class="btn-group btn-group-sm"><a class="btn btn-outline-success" href="?p=<?=enc(PATH)?>&act=edit&file=<?=urlencode($f)?>"><i class="fa-solid fa-file-pen"></i></a><a class="btn btn-outline-primary" href="?p=<?=enc(PATH)?>&act=rename&file=<?=urlencode($f)?>"><i class="fa-regular fa-pen-to-square"></i></a><a class="btn btn-outline-warning" href="?p=<?=enc(PATH)?>&act=chmod&file=<?=urlencode($f)?>"><i class="fa-solid fa-key"></i></a><a class="btn btn-outline-danger" href="?p=<?=enc(PATH)?>&del=<?=urlencode($f)?>" onclick="return confirm('Delete file?')"><i class="fa-solid fa-trash"></i></a></div></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<!-- MODALS -->
<?php if(in_array($act,['upload','mkfile','mkdir','rename','edit','chmod','scan'])): ?>
<div class="modal fade show" style="display:block"><div class="modal-dialog <?=($act==='edit'||$act==='scan')?'modal-xl':'modal-dialog-centered';?>"><div class="modal-content">
  <?php if($act==='upload'): ?>
    <div class="modal-header glass"><h5 class="modal-title">Upload</h5></div>
    <div class="modal-body">
      <ul class="nav nav-tabs mb-3" role="tablist">
        <li class="nav-item" role="presentation">
          <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#upload-file" type="button">File Upload</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" data-bs-toggle="tab" data-bs-target="#upload-url" type="button">URL Upload</button>
        </li>
      </ul>
      <div class="tab-content">
        <div class="tab-pane fade show active" id="upload-file">
          <form method="post" enctype="multipart/form-data">
            <input class="form-control" type="file" name="file">
            <div class="mt-3 text-end">
              <button class="btn btn-secondary" onclick="history.back()">Cancel</button>
              <button class="btn btn-primary" name="upload">Upload</button>
            </div>
          </form>
        </div>
        <div class="tab-pane fade" id="upload-url">
          <form method="post">
            <input type="url" class="form-control" name="fileurl" placeholder="https://example.com/file.zip" required>
            <div class="mt-3 text-end">
              <button class="btn btn-secondary" onclick="history.back()">Cancel</button>
              <button class="btn btn-primary" name="url_upload">Download</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  <?php elseif($act==='mkfile'): ?>
    <div class="modal-header glass"><h5 class="modal-title">New file</h5></div>
    <form method="post"><div class="modal-body"><input class="form-control" name="filename" placeholder="example.txt" required></div><div class="modal-footer glass"><button class="btn btn-secondary" onclick="history.back()">Cancel</button><button class="btn btn-primary" name="mkfile">Create</button></div></form>
  <?php elseif($act==='mkdir'): ?>
    <div class="modal-header glass"><h5 class="modal-title">New folder</h5></div>
    <form method="post"><div class="modal-body"><input class="form-control" name="folder" placeholder="Folder name" required></div><div class="modal-footer glass"><button class="btn btn-secondary" onclick="history.back()">Cancel</button><button class="btn btn-primary" name="mkfolder">Create</button></div></form>
  <?php elseif($act==='rename'&&$target): ?>
    <div class="modal-header glass"><h5 class="modal-title">Rename</h5></div>
    <form method="post"><div class="modal-body"><input type="hidden" name="old" value="<?=htmlspecialchars($target)?>"><input class="form-control" name="new" value="<?=htmlspecialchars($target)?>"></div><div class="modal-footer glass"><button class="btn btn-secondary" onclick="history.back()">Cancel</button><button class="btn btn-primary" name="rename">Save</button></div></form>
  <?php elseif($act==='chmod'&&$target): ?>
    <div class="modal-header glass"><h5 class="modal-title">Change permissions</h5></div>
    <form method="post"><input type="hidden" name="file" value="<?=htmlspecialchars($target)?>"><div class="modal-body"><input class="form-control w-50 mx-auto text-center" name="mode" value="<?=perms(PATH.'/'.$target)?>" pattern="[0-7]{3}" maxlength="3"></div><div class="modal-footer glass"><button class="btn btn-secondary" onclick="history.back()">Cancel</button><button class="btn btn-primary" name="chmod">Apply</button></div></form>
  <?php elseif($act==='edit'&&$target): $fp=PATH.'/'.$target; ?>
    <div class="modal-header glass"><h5 class="modal-title">Editing <?=htmlspecialchars($target)?></h5></div>
    <form method="post" class="d-flex flex-column h-100"><div class="modal-body flex-grow-1 p-0"><textarea name="data" class="form-control h-100 border-0 rounded-0"><?=htmlspecialchars(file_get_contents($fp))?></textarea></div><div class="modal-footer glass"><button class="btn btn-secondary" onclick="history.back()">Cancel</button><button class="btn btn-primary" name="save">Save</button></div></form>
  <?php elseif($act==='scan'): ?>
    <div class="modal-header glass"><h5 class="modal-title">Malware scan – <?=htmlspecialchars(PATH)?></h5></div>
    <div class="modal-body" style="max-height:70vh;overflow:auto">
      <?php if(empty($scanResults)): ?>
        <div class="alert alert-success d-flex align-items-center gap-2"><i class="fa-solid fa-shield-halved"></i> <span>No suspicious patterns detected 🎉</span></div>
      <?php else: ?>
        <div class="alert alert-danger d-flex align-items-center gap-2 mb-4"><i class="fa-solid fa-triangle-exclamation"></i> <strong><?=count($scanResults)?></strong> suspicious file(s) found</div>
        <div class="table-responsive"><table class="table table-sm table-bordered align-middle">
          <thead class="table-light fixed-top"><tr><th>File</th><th>Match</th><th>Size</th></tr></thead><tbody>
          <?php foreach($scanResults as $hit): ?>
            <tr><td style="word-break:break-all"><?=str_replace($root,'',$hit['file'])?></td><td><code><?=$hit['sig']?></code></td><td><?=fmtSize($hit['size'])?></td></tr>
          <?php endforeach; ?>
          </tbody></table></div>
      <?php endif; ?>
    </div>
    <div class="modal-footer glass"><button class="btn btn-primary" onclick="history.back()">Close</button></div>
  <?php endif; ?>
</div></div></div><div class="modal-backdrop fade show"></div>
<?php endif; ?>

<footer class="text-center small py-3 glass mt-auto">© <?=date('Y')?> <a href="https://github.com/your-repo/aurorafile" class="text-decoration-none">AuroraFile</a></footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(e=>new bootstrap.Tooltip(e));
const html=document.documentElement,btn=document.getElementById('themeBtn');
function setTheme(t){html.setAttribute('data-bs-theme',t);localStorage.setItem('theme',t);} if(localStorage.getItem('theme')) setTheme(localStorage.getItem('theme'));
btn.onclick=()=>setTheme(html.getAttribute('data-bs-theme')==='dark'?'light':'dark');
</script>
</body>
</html>