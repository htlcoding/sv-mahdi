<?php
require_once './scripts/user_validation.php';
session_start();

$error="";

// Überprüfen, ob der Benutzer angemeldet ist; falls nicht, zur Anmeldeseite umleiten
if (!CheckLoggedIn()) {
    header('Location: ./login.php');
    exit;
}

// Fehleraktion behandeln
if (isset($_GET['action']) && $_GET['action'] === 'error') {
    $error = 'Ein Fehler ist beim Melden aufgetreten.';
}

try {
    // Datenbankkonfiguration laden
    require_once __DIR__ . '/scripts/configs_loader.php';
    $config = loadConfigFile();
    $dbHost = $config['DB_HOST'];
    $dbUser = $config['DB_USER'];
    $dbPass = $config['DB_PASS'];
    $dbName = $config['DB_NAME'];

    // Neue Datenbankverbindung erstellen
    $db = new mysqli($dbHost, $dbUser, $dbPass, $dbName);

    // Auf Datenbankverbindungsfehler überprüfen
    if ($db->connect_error) {
        header('Location: pages/cloud_unavailable.html');
        exit;
    }

    // Formularübermittlung behandeln
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['selected_option'])) {
            $selectedOptionIndex = $_POST['selected_option'];

            // Überprüfen, ob der Benutzer innerhalb der letzten 24 Stunden gemeldet hat
            $checkReportQuery = $db->prepare('SELECT report_timestamp FROM users WHERE id = ?');
            $checkReportQuery->bind_param('i', $_COOKIE['user_id']);
            $checkReportQuery->execute();
            $checkReportQuery->bind_result($lastReportTimestamp);
            $checkReportQuery->fetch();
            $checkReportQuery->close();

            if ($lastReportTimestamp && strtotime($lastReportTimestamp) > strtotime('-24 hours')) {
                $error = 'Du hast bereits innerhalb der letzten 24 Stunden gemeldet.';
            } else {
                // Überprüfen, ob der Benutzer innerhalb der letzten 48 Stunden dieselbe Option gemeldet hat
                $checkDuplicateQuery = $db->prepare('SELECT id FROM user_reports WHERE user_id = ? AND option_id = ? AND report_timestamp > NOW() - INTERVAL 48 HOUR');
                $checkDuplicateQuery->bind_param('ii', $_COOKIE['user_id'], $selectedOptionIndex);
                $checkDuplicateQuery->execute();
                $checkDuplicateQuery->store_result();

                if ($checkDuplicateQuery->num_rows > 0) {
                    $error = 'Du hast diese Option bereits innerhalb der letzten 48 Stunden gemeldet.';
                    exit;
                }

                // Tabelle "kontrollliste" mit dem Bericht aktualisieren
                $stmt = $db->prepare('UPDATE kontrollliste SET reports = reports + 1 WHERE id = ?');
                $stmt->bind_param('i', $selectedOptionIndex);
                $stmt->execute();

                // Tabelle "ranking" mit Guthaben aktualisieren
                $stmt = $db->prepare('UPDATE ranking SET credit = credit + 5 WHERE username = ?');
                $stmt->bind_param('s', $_COOKIE['username']); // Sitzungsbenutzernamen verwenden
                $stmt->execute();

                // In "user_reports" einfügen
                $insertReportQuery = $db->prepare('INSERT INTO user_reports (user_id, option_id) VALUES (?, ?)');
                $insertReportQuery->bind_param('ii', $_COOKIE['user_id'], $selectedOptionIndex);
                $insertReportQuery->execute();
                $insertReportQuery->close();

                // Den "report_timestamp" des Benutzers aktualisieren
                $updateLastReportedQuery = $db->prepare('UPDATE users SET report_timestamp = NOW() WHERE id = ?');
                $updateLastReportedQuery->bind_param('i', $_COOKIE['user_id']);
                $updateLastReportedQuery->execute();

                // Anzahl der Berichte nach 48 Stunden verringern
                $cleanupQuery = $db->prepare('UPDATE kontrollliste SET reports = reports - 1 WHERE id IN (SELECT option_id FROM user_reports WHERE report_timestamp < NOW() - INTERVAL 48 HOUR)');
                $cleanupQuery->execute();
                $cleanupQuery->close();

                // Mit Erfolgsmeldung umleiten
                header('Location: kontris.php?action=successreport');
                exit;
            }
        }
    }

    // Optionen aus der Datenbank abrufen
    $optionsQuery = $db->query('SELECT * FROM kontrollliste');
} catch (Exception $e) {
    header('Location: report.php?action=error');
} finally {
    // Datenbankverbindung schließen
    $db->close();
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Kontri Melden</title>
    <link rel="stylesheet" href="report.css">
</head>
<body>
    <h1>Kontri Melden</h1>
    <form method="post" action="">
        <label for="selected_option">Option auswählen:</label><br>
        <select name="selected_option" id="selected_option" required>
            <?php while ($option = $optionsQuery->fetch_assoc()): ?>
                <option value="<?php echo $option['id']; ?>"><?php echo htmlspecialchars($option['transport'] . ' ' . $option['line'] . ' ' . $option['station']); ?></option>
            <?php endwhile; ?>
        </select><br>
        <?php 
        echo $error; 
        ?>
        <p></p>
        <input type="submit" name="submit" value="Melden">
    </form>
</body>
</html>
