const express = require('express')
const cors = require('cors')
const cookieParse = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier')

// ---- config ----
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'alma_boci'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'


// --- cookie bealitas ---

const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path:'/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7nap

}

// --- adatbázis bealitaás

const db = mysql.createPool({
    host: 'localhost', //sulis szerver miatt majd átirodik
    port: '3306', //sulis szerver miatt majd átirodik
    user: 'root',
    password: '',
    database: 'szabazas'

})

// --- app ---
const app = express();

app.use(express.json())
app.use(cookieParse())
app.use(cors({
    origin:'*',
    credentials: true
}))
// --- végpontok ---
app.post('/regisztracio', async (req, res)=>{
    const {email, felhasznalonev, jelszo, admin} = req.body;
    //bemeneti adatok ellenőrése
    if(!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json({message: "jiamyzó bemeneti adatok"})
    }

    //ellenőrizni a felhazsnaloneve és emailt hogy egyedi e
    try {
        const isValid = await emailValidator(email)
        if (!isValid){
            return res.status(401).json({message: "nem valós email adtál meg"})
        }
        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE email = ? OR felhasznalonev = ?'
        const [exists] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev]);
        if (exists.length){
            return res.status(402).json({message: "az email cím vagy felhasznalonév már foglalt"})
        }

        const hash = await bcrypt.hash(jelszo,10);
        const regisztracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin])

        return res.status(200).json({
            message: "Sikeres regisztracio",
            id:result.insertId
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Szerverhiba"})
    }
})

app.post('/belepes', async (req, res) =>{
    const{felhasznalonevVagyEmail, jelszo} = req.body;
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({message: "hianyos belépesi adatok"})
    }
    try {
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = {}
    if (isValid) {

        const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [rows] = await db.query(sql, [felhasznalonevVagyEmail])

        if(rows.length){
         user = rows[0];
        hashJelszo= user.jelszo
    
    }else{
        return res.status(401).json({message: "Ezzel az email cimmel még nem regisztráltak"})
    }

}else{
    const sql= 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
    const[rows] = await db.query(sql, [felhasznalonevVagyEmail]);

    if(rows.length){
    user = rows[0];
    hashJelszo= user.jelszo;

}else{
    return res.status(402).json({message: "Ezzel az email cimmel még nem regisztráltak"})
    }
    
} 

    const ok = bcrypt.compare(jelszo, hashJelszo) //felhasznalonev tartozo jelzso
    if(!ok){
        return res.status(403).json({message:"Rossz jelszót adtál meg!"})
    }
    const token = jwt.sign(
        {id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin},
        JWT_SECRET,
        {expiresIn: JWT_EXPIRES_IN}
    )

        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message: "Sikeres belépés"})
    } catch (error) {
        console.log(error);
        return res.status(500).json({message: "szerverhiba"})
    }
})


app.get('/adataim', auth, async (req, res)=>{
    
})



// --- szerver elinditása ---
app.listen(PORT,HOST, ()=>{
    console.log(`http://${HOST}:${PORT}/`)
})