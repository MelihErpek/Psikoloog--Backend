var mongoose = require('mongoose')
const Schema = mongoose.Schema
const randevuSchema = new Schema({

    DoktorID:{
        type:String
    },
    HastaID:{
        type:String
    },
    DoktorAdSoyad:{
        type:String
    },
    HastaAdSoyad:{
        type:Buffer
    },
    RandevuBaslangic:{
        type:Date
    },
    RandevuBitis:{
        type:Date
    }
    

    
})
const Randevu = mongoose.model('Randevu',randevuSchema)

module.exports = Randevu;