require('dotenv').config({ path: __dirname + '/.env' })

const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const axios = require('axios')
const Subscription = require('./models/Subscription')

const app = express()
const PORT = process.env.PORT || 4000
const MONGO_URI = process.env.MONGO_URI
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173'
const ALLOWED_ORIGINS = FRONTEND_URL.split(',').map(u => u.trim())
const VC_TOKEN = process.env.VULNERABLECODE_TOKEN

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true)
    cb(new Error('Not allowed by CORS'))
  },
  methods: ['GET', 'POST'],
  credentials: true
}))
app.use(express.json())

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err))

// Proxy for VulnerableCode API (CORS fix) — GET
app.get('/vulnerablecode/*', async (req, res) => {
  try {
    const path = req.params[0]
    const query = new URLSearchParams(req.query).toString()
    const url = `https://public.vulnerablecode.io/api/${path}${query ? '?' + query : ''}`
    const response = await axios.get(url, {
      headers: { 'Authorization': `Token ${VC_TOKEN}` }
    })
    res.json(response.data)
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: 'Proxy error' })
  }
})

// Proxy for VulnerableCode API — POST (bulk_search etc)
app.post('/vulnerablecode/*', async (req, res) => {
  try {
    const path = req.params[0]
    const url = `https://public.vulnerablecode.io/api/${path}`
    const response = await axios.post(url, req.body, {
      headers: { 'Authorization': `Token ${VC_TOKEN}`, 'Content-Type': 'application/json' }
    })
    res.json(response.data)
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: 'Proxy error' })
  }
})

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
