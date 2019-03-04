function requireAuth(req, res, next){
  
  const authToken = req.get('Authorization') || '';

  if(!authToken.toLowerCase().startsWith('bearer ')){
    return res.status(401).json({error: 'Missing token'})
  }

  next()
}

module.exports = {
  requireAuth,
}