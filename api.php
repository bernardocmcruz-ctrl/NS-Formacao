<?php
session_start();
header('Content-Type: application/json; charset=utf-8');

// ── Ligação à BD ──
$host = getenv('DB_HOST') ?: 'localhost';
$user = getenv('DB_USER') ?: 'root';
$pass = getenv('DB_PASS') ?: '';
$db   = 'ns_estudo';

try {
    $con = new PDO(
        "mysql:host=$host;dbname=$db;charset=utf8mb4",
        $user, $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    jsonErr('Erro de ligação à base de dados.');
}

$action = trim($_POST['action'] ?? $_GET['action'] ?? '');

// ── Helpers ──
function jsonOk($data = []) {
    echo json_encode(['ok' => true, 'data' => $data]);
    exit;
}
function jsonErr($msg) {
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}
function uid() {
    return $_SESSION['ns_uid'] ?? null;
}

// ── Router ──
switch ($action) {

    // ── REGISTAR ──
    case 'registar':
        $nome  = trim($_POST['nome']  ?? '');
        $email = trim(strtolower($_POST['email'] ?? ''));
        $pw    = $_POST['password'] ?? '';

        if (!$nome || !$email || !$pw)          jsonErr('Preenche todos os campos.');
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonErr('Email inválido.');
        if (strlen($pw) < 6)                    jsonErr('A password deve ter pelo menos 6 caracteres.');

        $stmt = $con->prepare('SELECT id FROM utilizadores WHERE email = ?');
        $stmt->execute([$email]);
        if ($stmt->fetch()) jsonErr('Este email já está registado.');

        $hash = password_hash($pw, PASSWORD_DEFAULT);
        $stmt = $con->prepare('INSERT INTO utilizadores (nome, email, password_hash) VALUES (?,?,?)');
        $stmt->execute([$nome, $email, $hash]);

        $_SESSION['ns_uid']   = (int)$con->lastInsertId();
        $_SESSION['ns_nome']  = $nome;
        jsonOk(['id' => $_SESSION['ns_uid'], 'nome' => $nome]);

    // ── LOGIN ──
    case 'login':
        $email = trim(strtolower($_POST['email'] ?? ''));
        $pw    = $_POST['password'] ?? '';

        $stmt = $con->prepare('SELECT * FROM utilizadores WHERE email = ?');
        $stmt->execute([$email]);
        $u = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$u || !password_verify($pw, $u['password_hash'])) {
            jsonErr('Email ou password incorretos.');
        }

        $_SESSION['ns_uid']  = (int)$u['id'];
        $_SESSION['ns_nome'] = $u['nome'];
        jsonOk(['id' => (int)$u['id'], 'nome' => $u['nome']]);

    // ── LOGOUT ──
    case 'logout':
        unset($_SESSION['ns_uid'], $_SESSION['ns_nome']);
        jsonOk();

    // ── SESSÃO ACTUAL ──
    case 'sessao':
        if (uid()) {
            jsonOk(['id' => uid(), 'nome' => $_SESSION['ns_nome']]);
        } else {
            jsonOk(['id' => null]);
        }

    // ── GUARDAR SESSÃO DE QUIZ ──
    case 'guardar_sessao':
        if (!uid()) jsonErr('Não autenticado.');

        $stmt = $con->prepare('
            INSERT INTO sessoes_quiz
                (user_id, capitulo, modo, score, total, pct, earned_pts, total_pts, duracao)
            VALUES (?,?,?,?,?,?,?,?,?)
        ');
        $stmt->execute([
            uid(),
            $_POST['capitulo']   ?? '',
            $_POST['modo']       ?? 'chapter',
            (int)($_POST['score']      ?? 0),
            (int)($_POST['total']      ?? 0),
            (int)($_POST['pct']        ?? 0),
            (int)($_POST['earned_pts'] ?? 0),
            (int)($_POST['total_pts']  ?? 0),
            (int)($_POST['duracao']    ?? 0),
        ]);
        jsonOk();

    // ── GUARDAR STAT DE PERGUNTA ──
    case 'guardar_pergunta':
        if (!uid()) jsonErr('Não autenticado.');

        $qid     = $_POST['pergunta_id'] ?? '';
        $correct = (int)($_POST['correct'] ?? 0);
        $c = $correct ? 1 : 0;
        $e = $correct ? 0 : 1;

        $stmt = $con->prepare('
            INSERT INTO stats_perguntas (user_id, pergunta_id, corretas, erradas)
            VALUES (?,?,?,?)
            ON DUPLICATE KEY UPDATE
                corretas  = corretas  + VALUES(corretas),
                erradas   = erradas   + VALUES(erradas),
                updated_at = NOW()
        ');
        $stmt->execute([uid(), $qid, $c, $e]);
        jsonOk();

    // ── CARREGAR STATS ──
    case 'carregar_stats':
        if (!uid()) jsonOk(['sessoes' => [], 'perguntas' => []]);

        $stmt = $con->prepare('
            SELECT capitulo, modo, score, total, pct, earned_pts, total_pts, duracao,
                   UNIX_TIMESTAMP(created_at)*1000 AS ts
            FROM sessoes_quiz WHERE user_id = ? ORDER BY created_at ASC
        ');
        $stmt->execute([uid()]);
        $sessoes = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $stmt = $con->prepare('
            SELECT pergunta_id, corretas, erradas
            FROM stats_perguntas WHERE user_id = ?
        ');
        $stmt->execute([uid()]);
        $perguntas = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Normaliza tipos
        foreach ($sessoes   as &$s) { $s['score']=(int)$s['score'];$s['total']=(int)$s['total'];$s['pct']=(int)$s['pct']; }
        foreach ($perguntas as &$p) { $p['corretas']=(int)$p['corretas'];$p['erradas']=(int)$p['erradas']; }

        jsonOk(['sessoes' => $sessoes, 'perguntas' => $perguntas]);

    default:
        jsonErr('Acção desconhecida.');
}
