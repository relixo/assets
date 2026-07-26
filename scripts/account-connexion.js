import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const SUPABASE_URL = 'https://iycpjauzezqsiomcvuta.supabase.co'
const SUPABASE_ANON_KEY = 'sb_publishable_bJfHC7Bw48n1auejJkcxsg_f1KoPSd-'

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// Fonction utilitaire pour générer une clé secrète aléatoire forte
function generateSecretKey() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Chiffrement d'une chaîne avec une clé secrète (utilisant l'API Web Crypto)
async function encryptData(text, secretKey) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(secretKey.slice(0, 32).padEnd(32, '0')),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(text)
    );
    
    // Combine salt, iv et données chiffrées dans une seule chaîne en base64
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    return btoa(String.fromCharCode(...combined));
}

// Déchiffrement
async function decryptData(encryptedBase64, secretKey) {
    try {
        const enc = new TextEncoder();
        const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const data = combined.slice(28);
        
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(secretKey.slice(0, 32).padEnd(32, '0')),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        
        const key = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
    
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        return null; // Échec du déchiffrement (mauvaise clé)
    }
}

// --- GESTION DE LA CRÉATION DE COMPTE ---
document.getElementById('create-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('create-username').value.trim();
    
    // Génération de la clé secrète locale
    const secretKey = generateSecretKey();
    
    // On crypte une phrase témoin "acces_granted" avec cette clé
    const cryptedValue = await encryptData("acces_granted", secretKey);
    
    // Enregistrement dans Supabase (le serveur ne connaît QUE le résultat crypté)
    const { data, error } = await supabase
        .from('accounts')
        .insert([
            { 
                name: username, 
                display_name: username, 
                crypted: cryptedValue 
            }
        ]);

    if (error) {
        alert("Erreur lors de la création : " + error.message);
        return;
    }

    // Téléchargement automatique de la clé secrète dans KEY.txt
    const blob = new Blob([secretKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `KEY_${username}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert("Compte créé avec succès ! Votre fichier KEY.txt a été téléchargé. Conservez-le précieusement.");
});

// --- GESTION DE LA CONNEXION ---
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const fileInput = document.getElementById('login-keyfile'); // Assurez-vous d'avoir un input type="file" dans votre HTML de login
    const file = fileInput?.files[0];

    if (!file) {
        alert("Veuillez sélectionner votre fichier KEY.txt");
        return;
    }

    const reader = new FileReader();
    reader.onload = async function(event) {
        const secretKey = event.target.result.trim();

        // Récupération des données du compte depuis Supabase
        const { data, error } = await supabase
            .from('accounts')
            .select('*')
            .eq('name', username)
            .single();

        if (error || !data) {
            alert("Compte introuvable.");
            return;
        }

        // Tentative de déchiffrement du champ crypted avec la clé du fichier
        const decrypted = await decryptData(data.crypted, secretKey);

        if (decrypted === "acces_granted") {
            // Connexion réussie : enregistrement dans le localStorage
            localStorage.setItem('username', username);
            localStorage.setItem('key', secretKey);
            alert("Connexion réussie ! Redirection...");
            window.location.href = "/feed/"; // ou la page d'accueil de l'app
        } else {
            alert("Clé invalide ou fichier incorrect.");
        }
    };

    reader.readAsText(file);
});
