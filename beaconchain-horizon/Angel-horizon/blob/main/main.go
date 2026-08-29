package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "io"
    "log"
    "math/big"
    "net"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/go-sql-driver/mysql"
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
)

// ==========================================
// 1. Database and Global State
// ==========================================
var DB *sql.DB
var PrivateKey *ecdsa.PrivateKey
var isSystemActive = false

func InitDB() {
    dsn := os.Getenv("DATABASE_URL")
    if dsn == "" {
        dsn = "root:b1a5iQGqyrvzjxPaCXFe9ktw@tcp(hosted-net:3306)/practical_hoover"
    }
    var err error
    DB, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal("DB connection error:", err)
    }

    // Create tables
    _, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS validators (
            idx INT PRIMARY KEY,
            status VARCHAR(50),
            balance DOUBLE
        );
        CREATE TABLE IF NOT EXISTS licenses (
            id VARCHAR(100) PRIMARY KEY,
            product_id VARCHAR(100),
            user_id VARCHAR(100),
            volume INT,
            root TEXT,
            seed TEXT,
            created_at DATETIME,
            expires_at DATETIME,
            active BOOLEAN,
            signature TEXT
        );
        CREATE TABLE IF NOT EXISTS keys (
            id INT PRIMARY KEY AUTO_INCREMENT,
            private_key TEXT
        );
    `)
    if err != nil {
        log.Fatal("Table creation error:", err)
    }

    // Load existing private key
    var privPEM string
    err = DB.QueryRow("SELECT private_key FROM keys LIMIT 1").Scan(&privPEM)
    if err == nil && privPEM != "" {
        block, _ := pem.Decode([]byte(privPEM))
        if block != nil {
            priv, err := x509.ParseECPrivateKey(block.Bytes)
            if err == nil {
                PrivateKey = priv
            }
        }
    }
}

// ==========================================
// 2. Cryptography Functions
// ==========================================
func SHA256Hash(data []byte) string {
    h := sha256.Sum256(data)
    return hex.EncodeToString(h[:])
}

func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    return priv, nil
}

func SignData(priv *ecdsa.PrivateKey, data []byte) string {
    hash := sha256.Sum256(data)
    r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
    sig := append(r.Bytes(), s.Bytes()...)
    return hex.EncodeToString(sig)
}

func VerifySignature(pub *ecdsa.PublicKey, data []byte, sigHex string) bool {
    sig, _ := hex.DecodeString(sigHex)
    if len(sig) < 64 {
        return false
    }
    r := new(big.Int).SetBytes(sig[:len(sig)/2])
    s := new(big.Int).SetBytes(sig[len(sig)/2:])
    hash := sha256.Sum256(data)
    return ecdsa.Verify(pub, hash[:], r, s)
}

func EncryptAES(key []byte, text string) (string, error) {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ct := gcm.Seal(nonce, nonce, []byte(text), nil)
    return base64.StdEncoding.EncodeToString(ct), nil
}

func DecryptAES(key []byte, ctBase64 string) (string, error) {
    ct, _ := base64.StdEncoding.DecodeString(ctBase64)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce, ct := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
    pt, _ := gcm.Open(nil, nonce, ct, nil)
    return string(pt), nil
}

// ==========================================
// 3. Merkle License Functions
// ==========================================
type LicenseInfo struct {
    ID        string    `json:"id"`
    ProductID string    `json:"product_id"`
    UserID    string    `json:"user_id"`
    CreatedAt time.Time `json:"created_at"`
    ExpiresAt time.Time `json:"expires_at"`
    Active    bool      `json:"active"`
    Signature string    `json:"signature"`
    RootHash  string    `json:"root_hash"`
}

func GenerateLicense(productID, userID string, duration time.Duration) (LicenseInfo, error) {
    data := map[string]interface{}{"pid": productID, "uid": userID, "exp": time.Now().UTC().Add(duration)}
    jsonData, _ := json.Marshal(data)
    root := SHA256Hash(jsonData)

    lic := LicenseInfo{
        ID:        "lic_" + strconv.FormatInt(time.Now().UnixNano(), 10),
        ProductID: productID,
        UserID:    userID,
        CreatedAt: time.Now().UTC(),
        ExpiresAt: time.Now().UTC().Add(duration),
        Active:    true,
        RootHash:  root,
    }

    lic.Signature = SignData(PrivateKey, []byte(root+":"+productID))

    _, err := DB.Exec("INSERT INTO licenses (id, product_id, user_id, root, created_at, expires_at, active, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        lic.ID, lic.ProductID, lic.UserID, lic.RootHash, lic.CreatedAt, lic.ExpiresAt, lic.Active, lic.Signature)
    return lic, err
}

// ==========================================
// 4. Network Tools
// ==========================================
func CalculateSubnet(cidr string) map[string]interface{} {
    _, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return map[string]interface{}{"error": "bad cidr"}
    }
    ones, bits := ipnet.Mask.Size()
    return map[string]interface{}{
        "network": ipnet.IP.String(),
        "total":   1 << (bits - ones),
        "prefix":  ones,
    }
}

func LookupOUI(mac string) string {
    mac = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":"))
    parts := strings.Split(mac, ":")
    if len(parts) < 3 {
        return "invalid"
    }
    db := map[string]string{"00:1A:2B": "Cisco", "00:0C:29": "VMware", "00:1E:8C": "Apple"}
    if v, ok := db[strings.Join(parts[:3], ":")]; ok {
        return v
    }
    return "Unknown"
}

// ==========================================
// 5. Middleware and API Handlers
// ==========================================
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("X-API-Key")
        if token != os.Getenv("API_KEY") {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func RequireSystemActive(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !isSystemActive {
            http.Error(w, "System is not initialized. Call /api/v1/init first.", http.StatusServiceUnavailable)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func InitSystemHandler(w http.ResponseWriter, r *http.Request) {
    if isSystemActive {
        json.NewEncoder(w).Encode(map[string]string{"status": "already_active"})
        return
    }

    providedKey := r.Header.Get("X-Admin-Key")
    if providedKey != os.Getenv("ADMIN_TOKEN") {
        http.Error(w, "Invalid Init Key", http.StatusUnauthorized)
        return
    }

    InitDB()

    if PrivateKey == nil {
        priv, _ := GenerateKeyPair()
        privBytes, _ := x509.MarshalECPrivateKey(priv)
        pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
        DB.Exec("INSERT INTO keys (private_key) VALUES (?)", pemStr)
        PrivateKey = priv
        log.Println("ECDSA Key generated and stored.")
    } else {
        log.Println("ECDSA Key loaded from DB.")
    }

    seed := []byte("HORIZON_MASTER_SEED_2026")
    log.Printf("Merkle Tree ready with Seed: %s", SHA256Hash(seed))

    isSystemActive = true
    log.Println("Horizon Core Engine initialized successfully!")

    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":          "initialized",
        "merkle_ready":    true,
        "ecdsa_key_ready": true,
        "time":            time.Now().UTC(),
    })
}

func ShutdownSystemHandler(w http.ResponseWriter, r *http.Request) {
    providedKey := r.Header.Get("X-Admin-Key")
    if providedKey != os.Getenv("ADMIN_TOKEN") {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    isSystemActive = false
    json.NewEncoder(w).Encode(map[string]string{"status": "system_shutdown"})
}

func GenerateLicenseHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ProductID string `json:"product_id"`
        UserID    string `json:"user_id"`
        Duration  int64  `json:"duration"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    lic, err := GenerateLicense(req.ProductID, req.UserID, time.Duration(req.Duration)*time.Hour)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    json.NewEncoder(w).Encode(lic)
}

func ListLicensesHandler(w http.ResponseWriter, r *http.Request) {
    rows, _ := DB.Query("SELECT id, product_id, user_id, root, created_at, expires_at, active FROM licenses")
    defer rows.Close()
    var lics []map[string]interface{}
    for rows.Next() {
        var id, pid, uid, root string
        var ca, ex time.Time
        var act bool
        rows.Scan(&id, &pid, &uid, &root, &ca, &ex, &act)
        lics = append(lics, map[string]interface{}{"id": id, "pid": pid, "uid": uid, "root": root, "exp": ex, "active": act})
    }
    json.NewEncoder(w).Encode(lics)
}

func EncryptHandler(w http.ResponseWriter, r *http.Request) {
    var req struct{ Key, Text string }
    json.NewDecoder(r.Body).Decode(&req)
    key, _ := hex.DecodeString(req.Key)
    res, err := EncryptAES(key, req.Text)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"cipher": res})
}

func DecryptHandler(w http.ResponseWriter, r *http.Request) {
    var req struct{ Key, Cipher string }
    json.NewDecoder(r.Body).Decode(&req)
    key, _ := hex.DecodeString(req.Key)
    res, err := DecryptAES(key, req.Cipher)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"plain": res})
}

func SubnetHandler(w http.ResponseWriter, r *http.Request) {
    cidr := r.URL.Query().Get("cidr")
    json.NewEncoder(w).Encode(CalculateSubnet(cidr))
}

func MacHandler(w http.ResponseWriter, r *http.Request) {
    mac := r.URL.Query().Get("mac")
    json.NewEncoder(w).Encode(map[string]string{"vendor": LookupOUI(mac)})
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]string{"status": "ok", "db": "connected"})
}

// ==========================================
// 6. Main Server Entrypoint
// ==========================================
func main() {
    godotenv.Load()

    r := mux.NewRouter()
    api := r.PathPrefix("/api/v1").Subrouter()

    // Public and Admin routes for Initialization/Shutdown
    api.HandleFunc("/init", InitSystemHandler).Methods("POST")
    api.HandleFunc("/shutdown", ShutdownSystemHandler).Methods("POST")

    // Protected Routes
    protected := api.NewRoute().Subrouter()
    protected.Use(AuthMiddleware)
    protected.Use(RequireSystemActive)

    protected.HandleFunc("/license/generate", GenerateLicenseHandler).Methods("POST")
    protected.HandleFunc("/licenses", ListLicensesHandler).Methods("GET")
    protected.HandleFunc("/toolbox/encrypt", EncryptHandler).Methods("POST")
    protected.HandleFunc("/toolbox/decrypt", DecryptHandler).Methods("POST")
    protected.HandleFunc("/toolbox/subnet", SubnetHandler).Methods("GET")
    protected.HandleFunc("/toolbox/mac", MacHandler).Methods("GET")
    protected.HandleFunc("/health", HealthHandler).Methods("GET")

    port := os.Getenv("SERVER_PORT")
    if port == "" {
        port = "8080"
    }

    log.Println("System is waiting for the Admin Panel to initialize...")
    log.Fatal(http.ListenAndServe(":"+port, r))
}
