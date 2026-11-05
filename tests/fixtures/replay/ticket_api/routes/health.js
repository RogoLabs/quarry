const express = require('express')
const pkg = require('../package.json')

const router = express.Router()

router.get('/health', (req, res) => res.json({ ok: true }))
router.get('/version', (req, res) => res.json({ version: pkg.version }))

module.exports = router
