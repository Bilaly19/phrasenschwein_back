function ok(res, data, message = 'OK') {
  return res.json({ success: true, message, data });
}

function created(res, data, message = 'Erstellt') {
  return res.status(201).json({ success: true, message, data });
}

module.exports = { ok, created };
