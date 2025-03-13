require 'openssl'
require 'base64'

def encrypt(plaintext, key)
  iv = OpenSSL::Random.random_bytes(12)
  
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv

  ciphertext = cipher.update(plaintext) + cipher.final
  tag = cipher.auth_tag

  return iv, ciphertext, tag
end

puts "Informe a mensagem que deseja criptografar: "
plaintext = gets.chomp.to_s

key = OpenSSL::Random.random_bytes(32)

iv, ciphertext, tag = encrypt(plaintext, key)

puts "Chave em Base64 (guarde para descriptografar): #{Base64.strict_encode64(key)}"
puts "IV em Base64: #{Base64.strict_encode64(iv)}"
puts "Texto cifrado em Base64: #{Base64.strict_encode64(ciphertext)}"
puts "Tag em Base64: #{Base64.strict_encode64(tag)}"

File.open("encrypted_data.bin", "wb") do |file|
  file.puts(Base64.strict_encode64(iv))
  file.puts(Base64.strict_encode64(ciphertext))
  file.puts(Base64.strict_encode64(tag))
end

puts "Dados criptografados em 'encrypted_data.bin'"