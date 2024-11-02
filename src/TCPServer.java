import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

// Die Klasse TCPServer definiert einen einfachen HTTP-Server
public class TCPServer {
    public final int serverPort; // Port des Servers
    public boolean serviceRequested = true; // Flag, um den Serverbetrieb zu steuern
    public static final String ROOT_DIRECTORY = "Testweb"; // Wurzelverzeichnis für Dateien
    public static final String HTUSERS_FILE = ".htuser"; // Name der Datei mit Zugangsdaten

    // Konstruktor, um den Port für den Server zu setzen
    public TCPServer(int serverPort) {
        this.serverPort = serverPort;
    }

    // Methode zum Starten des Servers
    public void startServer() {
        ServerSocket serverSocket;

        try {
            System.err.println("Erstellen eines neuen HTTP Server Sockets auf Port " + serverPort);
            serverSocket = new ServerSocket(serverPort); // ServerSocket auf festgelegtem Port erstellen

            // Wartet, bis eine Verbindung angefordert wird
            while (serviceRequested) {
                System.err.println("HTTP Server wartet auf Verbindung - horcht auf Port " + serverPort);
                Socket clientSocket = serverSocket.accept(); // Akzeptiert eingehende Verbindungen
                (new HTTPWorkerThread(clientSocket, this)).start(); // Startet neuen Worker-Thread für jede Anfrage
            }
        } catch (IOException e) {
            System.err.println("Serverfehler: " + e.getMessage());
        }
    }

    // Hauptmethode zum Starten des Servers
    public static void main(String[] args) {
        TCPServer myServer = new TCPServer(50000); // Erstellen des Servers auf Port 60000
        myServer.startServer();
    }
}

// ----------------------------------------------------------------------------

// Klasse HTTPWorkerThread zur Bearbeitung von HTTP-Anfragen in separaten Threads
class HTTPWorkerThread extends Thread {
    private Socket socket; // Socket für die Verbindung zum Client
    private TCPServer server; // Referenz auf den Server
    private BufferedReader inFromClient; // Zum Lesen von Client-Anfragen
    private DataOutputStream outToClient; // Zum Senden von Antworten an den Client
    private final String CRLF = "\r\n"; // CRLF für HTTP-Protokoll
    private final String CHARSET = "UTF-8"; // Zeichensatz für die Kommunikation

    // Konstruktor zum Initialisieren des Sockets und der Server-Referenz
    public HTTPWorkerThread(Socket sock, TCPServer server) {
        this.socket = sock;
        this.server = server;
    }

    // Run-Methode, um die Client-Anfrage zu bearbeiten
    public void run() {
        System.err.println("HTTP Worker Thread bearbeitet die Anfrage!");

        try {
            inFromClient = new BufferedReader(new InputStreamReader(socket.getInputStream(), CHARSET));
            outToClient = new DataOutputStream(socket.getOutputStream());

            // Erste Zeile der Anfrage lesen (z.B., GET /index.html HTTP/1.1)
            String requestLine = inFromClient.readLine();

            // Speichern aller Header-Felder
            Map<String, String> headers = new HashMap<>();
            String headerLine;
            // Header-Felder lesen, bis eine Leerzeile kommt
            while ((headerLine = inFromClient.readLine()) != null && !headerLine.isEmpty()) {
                String[] headerParts = headerLine.split(": ", 2);
                if (headerParts.length == 2) {
                    headers.put(headerParts[0], headerParts[1]);
                }
            }

            // Überprüft die Autorisierung, falls eine .htuser-Datei vorhanden ist
            File htusersFile = new File(TCPServer.ROOT_DIRECTORY, TCPServer.HTUSERS_FILE);
            if (htusersFile.exists()) {
                String authHeader = headers.get("Authorization");
                if (authHeader == null || !checkAuthorization(authHeader)) {
                    sendUnauthorizedResponse(); // Fehler 401 senden, wenn keine Autorisierung
                    return;
                }
            }

            // Überprüft den User-Agent; nur Firefox wird zugelassen
            String userAgent = headers.get("User-Agent");
            if (userAgent == null || !userAgent.contains("Firefox")) {
                sendError(406, "Not Acceptable"); // Fehler 406 senden, wenn nicht Firefox
                return;
            }

            // Überprüfen, ob die Anfragezeile mit GET beginnt
            if (requestLine == null || !requestLine.startsWith("GET")) {
                sendError(400, "Bad Request"); // Fehler 400 senden, wenn kein GET
                return;
            }

            // Extrahiert den Dateipfad nach dem GET-Befehl
            String filePath = requestLine.split(" ")[1];
            // Default path ist index.html
            filePath = Objects.equals(filePath, "/") ?  "/index.html" : filePath;
            File file = new File(TCPServer.ROOT_DIRECTORY, filePath);

            // Prüft, ob die Datei vorhanden ist und kein Ordner
            if (!file.exists() || file.isDirectory()) {
                sendError(404, "Not Found"); // Fehler 404 senden, wenn Datei nicht gefunden
            } else {
                sendResponse(file); // Antwort senden, wenn Datei vorhanden
            }

            socket.close(); // Schließt die Verbindung
        } catch (IOException e) {
            System.err.println("Verbindungsfehler: " + e.getMessage());
        }
    }

    /**
     * Sendet eine 401 Unauthorized-Antwort und enthält einen WWW-Authenticate-Header,
     * um eine Authentifizierungsanforderung anzuzeigen.
     * Zeigt dem Client an, dass eine Basic-Authentifizierung benötigt wird, und gibt die Nachricht aus.
     * @throws IOException
     */
    private void sendUnauthorizedResponse() throws IOException {
        String response = "HTTP/1.0 401 Unauthorized\r\n" +
                "Content-Type: text/html\r\n" +
                "Content-Length: " + "Unauthorized".length() + "\r\n" +
                "WWW-Authenticate: Basic realm=\"WebServer\"\r\n\r\n" +
                "Unauthorized";
        outToClient.writeBytes(response);
    }

    // Methode zur Überprüfung der Autorisierung anhand der .htuser-Datei
    private boolean checkAuthorization(String authHeader) throws UnsupportedEncodingException {
        // Entfernt den "Basic "-Präfix aus dem Autorisierungs-Header, sodass nur der Base64-kodierte String übrig bleibt
        String base64Credentials = authHeader.replace("Basic ", "");

        // Dekodiert den Base64-String in das ursprüngliche Format "username:password" und speichert es in der Variable credentials
        String credentials = new String(Base64.getDecoder().decode(base64Credentials), CHARSET);

        // Versucht, die .htuser-Datei im Wurzelverzeichnis zu öffnen und zeilenweise zu lesen
        try (BufferedReader reader = new BufferedReader(new FileReader(new File(TCPServer.ROOT_DIRECTORY, TCPServer.HTUSERS_FILE)))) {
            String line;

            // Durchläuft jede Zeile der .htuser-Datei
            while ((line = reader.readLine()) != null) {
                // Wenn eine Zeile gefunden wird, die den dekodierten Anmeldeinformationen entspricht, ist die Autorisierung erfolgreich
                if (line.equals(credentials)) return true;
            }
        } catch (IOException e) {
            // Gibt eine Fehlermeldung aus, wenn es ein Problem beim Lesen der .htuser-Datei gibt
            System.err.println("Fehler beim Lesen der .htusers-Datei: " + e.getMessage());
        }

        // Wenn keine Übereinstimmung gefunden wurde, gibt die Methode false zurück, was bedeutet, dass die Autorisierung fehlgeschlagen ist
        return false;
    }

    // Methode zum Senden der Antwort mit dem angeforderten Inhalt
    private void sendResponse(File file) throws IOException {
        String contentType = getContentType(file.getName()); // Inhaltstyp ermitteln
        long contentLength = file.length(); // Dateigröße ermitteln

        // Header der Antwort senden
        outToClient.writeBytes("HTTP/1.0 200 OK" + CRLF);
        outToClient.writeBytes("Content-Type: " + contentType + CRLF);
        outToClient.writeBytes("Content-Length: " + contentLength + CRLF);
        outToClient.writeBytes(CRLF);
        outToClient.flush();

        // Dateiinhalt in Blöcken senden
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            byte[] buffer = new byte[5000];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                outToClient.write(buffer, 0, bytesRead);
            }
        }

        outToClient.flush();
        System.err.println("Antwort gesendet: 200 OK, Content-Type: " + contentType + "\nContent-Length: " + contentLength);
        System.err.println("------------------------------");
    }

    // Methode zum Senden von Fehlermeldungen
    private void sendError(int statusCode, String message) throws IOException {
        String response = "<html><body><h1>" + statusCode + " " + message + "</h1></body></html>";
        outToClient.writeBytes("HTTP/1.0 " + statusCode + " " + message + CRLF);
        outToClient.writeBytes("Content-Type: text/html" + CRLF);
        outToClient.writeBytes("Content-Length: " + response.length() + CRLF);
        outToClient.writeBytes(CRLF);
        outToClient.writeBytes(response);
        outToClient.flush();

        System.err.println("Fehler gesendet: " + statusCode + " " + message);
    }

    // Methode zur Bestimmung des MIME-Types basierend auf Dateiendung
    private String getContentType(String fileName) {
        if (fileName.endsWith(".html")) return "text/html";
        if (fileName.endsWith(".jpg")) return "image/jpeg";
        if (fileName.endsWith(".gif")) return "image/gif";
        if (fileName.endsWith(".pdf")) return "application/pdf";
        if (fileName.endsWith(".ico")) return "image/x-icon";
        return "application/octet-stream"; // Standardwert für unbekannte Dateitypen
    }
}
