require('dotenv').config({ path: __dirname + '/.env' })

const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const Subscription = require('./models/Subscription')

const app = express()
const PORT = process.env.PORT || 4000
const MONGO_URI = process.env.MONGO_URI
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173'

app.use(cors({
  origin: FRONTEND_URL,
  methods: ['GET', 'POST'],
  credentials: true
}))
app.use(express.json())

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err))

// POST /subscribe
app.post('/subscribe', async (req, res) => {
  const { email, purl } = req.body

  if (!email || !purl)
    return res.status(400).json({ error: 'Email and PURL are required.' })

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email))
    return res.status(400).json({ error: 'Invalid email address.' })

  try {
    const sub = await Subscription.create({ email, purl })
    res.json({ success: true, message: `Subscribed ${email} to ${purl}`, data: sub })
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ error: 'Already subscribed to this package.' })
    res.status(500).json({ error: 'Server error.' })
  }
})

// GET /subscriptions
app.get('/subscriptions', async (req, res) => {
  const subs = await Subscription.find().sort({ subscribedAt: -1 })
  res.json(subs)
})

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`))
