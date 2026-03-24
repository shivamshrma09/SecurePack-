const mongoose = require('mongoose')

const subscriptionSchema = new mongoose.Schema({
  email: { type: String, required: true, trim: true, lowercase: true },
  purl:  { type: String, required: true, trim: true },
  subscribedAt: { type: Date, default: Date.now }
})

subscriptionSchema.index({ email: 1, purl: 1 }, { unique: true })

module.exports = mongoose.model('Subscription', subscriptionSchema)
