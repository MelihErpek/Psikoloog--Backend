require('dotenv').config();
var express = require('express');
const favicon = require('express-favicon');
const path = require('path');
const http = require("http");
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var cors = require('cors');
var bcrypt = require('bcryptjs');
var nodemailer = require("nodemailer");
var jwt = require('jsonwebtoken')
var axios = require("axios")
var Iyzipay = require('iyzipay');
const { OAuth2Client } = require('google-auth-library');
var User = require('./Models/User')
var Doktor = require('./Models/Doktor')
var Admin = require('./Models/Admin')
var Randevu = require('./Models/Randevular')
const auth = require("./Middleware/Auth");
const client = new OAuth2Client("109597581602-qbhc5vt9tehonl2r25c84ljqj2c93k73.apps.googleusercontent.com");
const fetch = require('node-fetch');
const app = express();
const server = http.createServer(app);
const socket = require("socket.io");
const io = socket(server);
app.use(cors());
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true, parameterLimit: 100000000 }));

let port = process.env.PORT || 5000;

const users = {};

const socketToRoom = {};

var iyzipay = new Iyzipay({
    apiKey: "sandbox-XLqXswLZJzHdWJDzeGwngBjKCsKFp86Q",
    secretKey: "sandbox-lXsSvIR3WhDx4GvYoxf068FjPADrlAnT",
    uri: 'https://sandbox-api.iyzipay.com'
});

const url = "mongodb+srv://melihnode:meliherpek1@cluster0.g1oel.mongodb.net/Psikoloog?authSource=admin&replicaSet=atlas-77ie5j-shard-0&w=majority&readPreference=primary&appname=MongoDB%20Compass&retryWrites=true&ssl=true";


mongoose.connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true
},
    (err) => { if (err) { throw err } console.log("Mongoose ile bağlantı kuruldu.") })


io.on('connection', socket => {
    console.log("connection")
    socket.on("join room", roomID => {

        if (users[roomID]) {
            const length = users[roomID].length;
            if (length === 4) {
                socket.emit("room full");
                return;
            }

            users[roomID].push(socket.id);
        } else {

            users[roomID] = [socket.id];
        }
        socketToRoom[socket.id] = roomID;
        const usersInThisRoom = users[roomID].filter(id => id !== socket.id);

        socket.emit("all users", usersInThisRoom);
    });

    socket.on("sending signal", payload => {
        io.to(payload.userToSignal).emit('user joined', { signal: payload.signal, callerID: payload.callerID });
    });

    socket.on("returning signal", payload => {
        io.to(payload.callerID).emit('receiving returned signal', { signal: payload.signal, id: socket.id });
    });

    socket.on('disconnect', () => {
        const roomID = socketToRoom[socket.id];
        let room = users[roomID];
        if (room) {
            room = room.filter(id => id !== socket.id);
            users[roomID] = room;
        }
    });

});

app.get("/AdminEkle", async (req, res) => {
    const kullaniciAdi = "admin";
    const sifre = "123";
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(sifre, salt);
    Admin.create({
        kullaniciAdi,
        sifre: passwordHash
    }, err => {
        if (err) {
            console.log("hata")
        }
        else {
            console.log("başarılı")
        }

    })

})


app.post("/Register", async (req, res) => {
    const { AdSoyad, Mail, Sifre, baseImage } = req.body;
    if (!AdSoyad || !Mail || !Sifre || !baseImage) {
        res.status(400);
        return res.json({ hata: "Eksik alan bırakmayınız." })
    }
    const user = await Doktor.findOne({ Mail: Mail })
    if (user) {
        res.status(400);
        return res.json({ hata: "Bu E-Mail daha önce kullanılmıştır." })
    }
    var resim = baseImage.toString('base64');
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(Sifre, salt);
    Doktor.create({
        AdSoyad,
        Mail,
        Sifre: passwordHash,
        Fotograf: resim
    })

    res.json("okey")

})
app.post("/Login", async (req, res) => {
    const { Mail, Sifre } = req.body;
    if (!Mail || !Sifre) {
        res.status(400);
        return res.json({ hata: "Eksik alan bırakmayınız." })
    }
    const user = await Doktor.findOne({ Mail: Mail })
    if (!user) {
        res.status(400);
        return res.json({ hata: "Bu E-Mail ile kayıtlı bir kullanıcı yoktur." })
    }
    const isMatch = await bcrypt.compare(Sifre, user.Sifre);
    if (!isMatch) {
        res.status(400);
        return res.json({ hata: "Şifre Hatalı." })
    }
    const token = jwt.sign({ id: user._id }, 'melih');

    res.json({
        token,
        user

    });
})
app.post("/LoginDoktor", async (req, res) => {
    const { Mail, Sifre } = req.body;
    if (!Mail || !Sifre) {
        res.status(400);
        return res.json({ hata: "Eksik alan bırakmayınız." })
    }
    const user = await Doktor.findOne({ Mail: Mail })
    if (!user) {
        res.status(400);
        return res.json({ hata: "Bu E-Mail ile kayıtlı bir doktor yoktur." })
    }
    const isMatch = await bcrypt.compare(Sifre, user.Sifre);
    if (!isMatch) {
        res.status(400);
        return res.json({ hata: "Şifre Hatalı." })
    }
    const token = jwt.sign({ id: user._id }, 'melih');

    res.json({
        token,
        user

    });
})
app.post("/LoginWithGoogle", async (req, res) => {
    const { tokenId } = req.body;

    client.verifyIdToken({ idToken: tokenId, audience: "109597581602-qbhc5vt9tehonl2r25c84ljqj2c93k73.apps.googleusercontent.com" }).then(response => {
        const { email_verified, name, email } = response.payload;
        if (email_verified) {
            Doktor.findOne({ Mail: email }).exec(async (err, user) => {
                if (err) {
                    res.status(400)
                    return res.json({ hata: "Something went wrong." })
                }
                else {
                    if (user) {
                        const token = jwt.sign({ id: user._id }, 'melih');
                        res.json({
                            token,
                            user
                        });
                    }
                    else {
                        const Sifre = email + name;
                        const salt = await bcrypt.genSalt();
                        const passwordHash = await bcrypt.hash(Sifre, salt);
                        Doktor.create({
                            AdSoyad: name,
                            Mail: email,
                            Sifre: passwordHash,
                            Fotograf: "data:image/jpeg;base64,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"
                        })
                        res.json("okey");
                    }
                }
            });

        }
    });

})
app.post("/LoginWithFacebook", async (req, res) => {
    const { accessToken, userID } = req.body;
    let urlGraphFacebook = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`
    axios(urlGraphFacebook, {
        method: 'GET'
    })
        .then(response => {
            const { email, name } = response.data;
            Doktor.findOne({ Mail: email }).exec(async (err, user) => {
                if (err) {
                    res.status(400)
                    return res.json({ hata: "Something went wrong." })
                }
                else {
                    if (user) {
                        const token = jwt.sign({ id: user._id }, 'melih');
                        res.json({
                            token,
                            user
                        });
                    }
                    else {
                        const Sifre = email + name;
                        const salt = await bcrypt.genSalt();
                        const passwordHash = await bcrypt.hash(Sifre, salt);
                        Doktor.create({
                            AdSoyad: name,
                            Mail: email,
                            Sifre: passwordHash,
                            Fotograf: "data:image/jpeg;base64,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"
                        })
                    }
                }
            });
        });
})

app.post("/tokenIsValid", async (req, res) => {

    try {
        const token = req.header("x-auth-token");

        if (!token) return res.json(false);

        const verified = jwt.verify(token, 'melih');
        if (!verified) return res.json(false);

        const user = await User.findById(verified.id);
        if (!user) return res.json(false);

        return res.json(true);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post("/SifremiUnuttum", async (req, res) => {
    const { Mail } = req.body;
    if (!Mail) {
        res.status(400);
        return res.json({ hata: "Mail adresini giriniz." })
    }
    const user = await User.findOne({ Mail: Mail })
    if (!user) {
        res.status(400);
        res.json({ hata: "Bu E-Mail ile kayıtlı bir kullanıcı yoktur." })
    }

    const link = "http://localhost:3000/SifreYenile/" + user._id;
    var transfer = nodemailer.createTransport({
        service: "gmail",
        auth: {
            type: 'OAuth2',
            user: "melihnode@gmail.com",
            pass: "meliherpek1"
        }
    });

    var mailInfo = {
        from: "melih.erpek1@ogr.sakarya.edu.tr",
        to: Mail,
        subject: "Şifre İşlemi Hakkında",
        text: "Şifre İşlemi Hakkında",
        html: "<p>Şifre değiştirmek için <a href='" + link + "'>link</a> linkine tıklayınız.</p>"
    };

    transfer.sendMail(mailInfo, function (err) {
        if (err) { console.log(err); }
        else console.log("gönderildi")
    });

})

app.post("/SifreYenile", async (req, res) => {
    const { Sifre, id } = req.body;
    if (!Sifre || !id) {
        res.status(400);
        return res.json({ hata: "Şifre Giriniz." })
    }
    const user = await User.findById(id)
    if (!user) {
        res.status(400);
        res.json({ hata: "Böyle bir kullanıcı yoktur." })
    }
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(Sifre, salt);
    User.findByIdAndUpdate(id, {
        Sifre: passwordHash
    }).then(console.log("tamamdır"))
})
app.get("/log", auth, async (req, res) => {

    const user = await Doktor.findById(req.user);

    const buf = user.Fotograf.toString();


    res.json({
        AdSoyad: user.AdSoyad,
        Id: user._id,
        Mail: user.Mail,
        Randevular: user.Randevular,
        Fotograf: buf
    })
});

app.post("/Calendar", async (req, res) => {


    const { gercekTarihBaslangic, gercekTarihBitis, Mail } = req.body;

    await User.findOneAndUpdate({ Mail }, {

        $push: {
            Randevular: {
                baslangic: gercekTarihBaslangic,
                bitis: gercekTarihBitis
            }
        }
    }
    )
})

app.post("/TarihGetir", async (req, res) => {
    const id = req.body.id
    const user = await User.findById(id);

    res.json({
        tarihler: user.Randevular
    })
    /*const tarihler = await User.findOne({ Mail: "meliherpek26@gmail.com" })
    //console.log(tarihler);
    res.json({
      tarihler: tarihler.Randevular
    })*/
})

app.get("/DoktorBul", async (req, res) => {
    let user = await User.find({});

    let newUser = [];
    user.map(item => {
        newUser.push({
            _id: item._id,
            AdSoyad: item.AdSoyad,
            Mail: item.Mail,
            Fotograf: item.Fotograf.toString()

        })
    })

    res.json({
        user: newUser


    })
})

app.post("/ProfilBul", async (req, res) => {
    const id = req.body.id
    const user = await User.findById(id);
    const buf = user.Fotograf.toString();
    res.json({
        user,
        Fotograf: buf
    })
})

app.post("/BildirimGonder", async (req, res) => {

    const gonderilenId = req.body.gonderilenKisi;
    const gonderen = await User.findById(req.body.gonderenKisi)
    const user = await User.findByIdAndUpdate(gonderilenId, {
        $push: {
            Bildirimler: {
                gonderenKisiAdSoyad: gonderen.AdSoyad,
                gonderenKisi: req.body.gonderenKisi,
                baslangic: req.body.baslangic,
                bitis: req.body.bitis
            }
        }
    });

})
app.post("/BildirimGetir", async (req, res) => {
    const id = req.body.id;
    const user = await User.findById(id)
    res.json({
        Bildirimler: user.Bildirimler
    })
})

app.post("/loggedIn", async (req, res) => {
    try {
        const token = req.header("x-auth-token");

        if (!token) return res.json(false);

        jwt.verify(token, "melih");

        res.send(true);
    } catch (err) {
        res.json(false);
    }
})

app.get("/try", async (req, res) => {
    var request = {
        locale: Iyzipay.LOCALE.TR,
        conversationId: '123456789',
        price: '1',
        paidPrice: '1.2',
        currency: Iyzipay.CURRENCY.TRY,
        basketId: 'B67832',
        paymentGroup: Iyzipay.PAYMENT_GROUP.LISTING,
        callbackUrl: 'https://www.merchant.com/callback',
        enabledInstallments: [2, 3, 6, 9],
        buyer: {
            id: 'BY789',
            name: 'John',
            surname: 'Doe',
            gsmNumber: '+905350000000',
            email: 'email@email.com',
            identityNumber: '74300864791',
            lastLoginDate: '2015-10-05 12:43:35',
            registrationDate: '2013-04-21 15:12:09',
            registrationAddress: 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
            ip: '85.34.78.112',
            city: 'Istanbul',
            country: 'Turkey',
            zipCode: '34732'
        },
        shippingAddress: {
            contactName: 'Jane Doe',
            city: 'Istanbul',
            country: 'Turkey',
            address: 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
            zipCode: '34742'
        },
        billingAddress: {
            contactName: 'Jane Doe',
            city: 'Istanbul',
            country: 'Turkey',
            address: 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
            zipCode: '34742'
        },
        basketItems: [
            {
                id: 'BI101',
                name: 'Binocular',
                category1: 'Collectibles',
                category2: 'Accessories',
                itemType: Iyzipay.BASKET_ITEM_TYPE.PHYSICAL,
                price: '0.3'
            },
            {
                id: 'BI102',
                name: 'Game code',
                category1: 'Game',
                category2: 'Online Game Items',
                itemType: Iyzipay.BASKET_ITEM_TYPE.VIRTUAL,
                price: '0.5'
            },
            {
                id: 'BI103',
                name: 'Usb',
                category1: 'Electronics',
                category2: 'Usb / Cable',
                itemType: Iyzipay.BASKET_ITEM_TYPE.PHYSICAL,
                price: '0.2'
            }
        ]
    };
    iyzipay.checkoutFormInitialize.create(request, function (err, result) {
        res.send(result.checkoutFormContent)
    });
})





app.listen(port);