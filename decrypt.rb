require 'openssl'
require 'base64'

def decrypt(iv, ciphertext, tag, key)
  # Objeto da cifra de AES-GCM
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key = key
  cipher.iv = iv
  cipher.auth_tag = tag

  # Descriptografar o texto
  plaintext = cipher.update(ciphertext) + cipher.final

  return plaintext
end

iv = nil
ciphertext = nil
tag = nil

begin
  File.open("encrypted_data.bin", "rb") do |file|
    data = file.read

    if data.empty?
      raise "O arquivo 'encrypted_data.bin' está vazio ou não foi gerado corretamente."
    end

    iv_base64, ciphertext_base64, tag_base64 = data.lines.map(&:chomp)

    iv = Base64.strict_decode64(iv_base64)
    ciphertext = Base64.strict_decode64(ciphertext_base64)
    tag = Base64.strict_decode64(tag_base64)
  end
rescue Errno::ENOENT
  puts "Erro: O arquivo 'encrypted_data.bin' não foi encontrado."
  exit
rescue StandardError => e
  puts "Erro ao ler o arquivo: #{e.message}"
  exit
end

puts "Insira a chave (em Base64): "
key_base64 = gets.chomp
key = Base64.strict_decode64(key_base64)

begin
  decrypted_text = decrypt(iv, ciphertext, tag, key)
  puts "Texto descriptografado: #{decrypted_text}"
rescue OpenSSL::Cipher::CipherError => e
  puts "Erro ao descriptografar: #{e.message}"
end