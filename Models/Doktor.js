var mongoose = require('mongoose')
const Schema = mongoose.Schema
const doktorSchema = new Schema({

    AdSoyad:{
        type:String
    },
    Mail:{
        type:String
    },
    Sifre:{
        type:String
    },
    Fotograf:{
        type:Buffer
    },
    Randevular:[{
        baslik:{type:String},
        baslangic:{type:Date},
        bitis:{type:Date}
    }],
    Bildirimler:[{
        gonderenKisi:{type:String},
        gonderenKisiAdSoyad:{type:String},
        baslangic:{type:Date},
        bitis:{type:Date}
    }]



    
})
const Doktor = mongoose.model('Doktor',doktorSchema)

module.exports = Doktor;