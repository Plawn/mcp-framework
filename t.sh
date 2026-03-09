TOKEN="EAAcJl65PBCIBQ9bJy1IZCzYqLWoRZCBHqjWZAH1onJqR8umdteeN9Pnf927ZCfHNsdMQlOmhvHJZAdWSyCtSZCxyCdZBLyWFzZAxBLNUlbuJcJVSWLS9ZA0ga7HTiA7qxiXC4PsB40dwq6AuZB7XnBRriLJwHtgYiyLZATxcuZARwQ0ETwO9oOtxlkhLF4hH3i4ZCNpRXsEuOiQhHZCk2C5dYmLvgQZAUvkDWbNKqBHC9KkZATDeRlDdae36eiAhTaNZAuFsxFeItJ8aiXzopKvbqDuyAgIHJaUIMLQZDZD"
ACT="784584835013241"
PAGE_TOKEN="EAAcJl65PBCIBQyLdFsOF14m5MA5HM7UysvK5JVeZCbDwJGeIzvxQKZBiSudD7ZB2ZBVIE1nuUwmqMcPQGpzJjONZC9amfZBHm9yPZCJjVrIIDJveF0AEr65XnC3WgZCZAehcwpthwlEyRGYJLnb1HZB7psFHIWm4KCgp5urx8yzXDVwR7Co3zZBhvPH88sj7GDoVuZC7MIThTOboJg67Varw3CVYDuNGtoU6yv7peXbZBgD2QUZBQZD"

# # lister les ads
# curl -G \
#   -d "fields=id,name,creative{id}" \
#   -d "access_token=$PAGE_TOKEN" \
#   "https://graph.facebook.com/v25.0/act_$ACT/ads"


curl -G \
  -d "fields=id,effective_object_story_id,object_story_id,object_story_spec" \
  -d "access_token=$PAGE_TOKEN" \
  "https://graph.facebook.com/v25.0/1888984595320742"


# curl -G \
#   -d "fields=id,message,from,created_time,like_count,comment_count,parent{id,message},url" \
#   -d "access_token=$PAGE_TOKEN" \
#   "https://graph.facebook.com/v25.0/1490493851271464_948262334524887/comments"


# curl -G \
#   -d "access_token=EAAcJl65PBCIBQZBfZAQKyFRbXqI023tdVNBfniAwYMdKN6XPntZCi1MiBlwebv8RPJ6WBVcrIkDd77ls7obxCMeZAcPwp5iBECen0rDqBE7AVP0OgrgcVhZBFOmGplQWz3cNVven1J20ZChwGW6W5kQA7dxDDXXqDFD8nNCUPWTZBZCWeuUKqJi2UEHeSKPC2eeKG7ezIDYitK9yd24c04j8O19vYOLHq3RQbgj4Fi6ApGfMxoMVLtZA1NFA9rrdbfT8RoEmd5UJDnf9p8yIZD" \
#   "https://graph.facebook.com/v25.0/me/accounts"