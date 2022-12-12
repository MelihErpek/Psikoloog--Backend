var mongoose = require('mongoose')
const Schema = mongoose.Schema
const userSchema = new Schema({

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
const User = mongoose.model('User',userSchema)

module.exports = User;