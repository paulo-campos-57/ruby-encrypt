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

def decrypt(iv, ciphertext, tag, key)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key = key
  cipher.iv = iv
  cipher.auth_tag = tag

  plaintext = cipher.update(ciphertext) + cipher.final

  return plaintext
end

def save_encrypted_message(iv, ciphertext, tag, filename)
  File.open(filename, "wb") do |file|
    file.puts(Base64.strict_encode64(iv))
    file.puts(Base64.strict_encode64(ciphertext))
    file.puts(Base64.strict_encode64(tag))
  end
  puts "Mensagem criptografada salva em '#{filename}'"
end

def load_encrypted_message(filename)
  iv = nil
  ciphertext = nil
  tag = nil

  begin
    File.open(filename, "rb") do |file|
      data = file.read

      if data.empty?
        raise "O arquivo '#{filename}' está vazio ou não foi gerado corretamente."
      end

      iv_base64, ciphertext_base64, tag_base64 = data.lines.map(&:chomp)

      iv = Base64.strict_decode64(iv_base64)
      ciphertext = Base64.strict_decode64(ciphertext_base64)
      tag = Base64.strict_decode64(tag_base64)
    end
  rescue Errno::ENOENT
    puts "Erro: O arquivo '#{filename}' não foi encontrado."
    return nil, nil, nil
  rescue StandardError => e
    puts "Erro ao ler o arquivo: #{e.message}"
    return nil, nil, nil
  end

  return iv, ciphertext, tag
end

loop do
  puts "\nEscolha uma opção:"
  puts "1. Criptografar uma mensagem"
  puts "2. Descriptografar uma mensagem"
  puts "3. Sair"
  print "Opção: "
  option = gets.chomp.to_i

  case option
  when 1
    puts "Informe a mensagem que deseja criptografar: "
    plaintext = gets.chomp.to_s

    puts "Informe um nome para o arquivo (ex: mensagem1.bin): "
    filename = gets.chomp

    key = OpenSSL::Random.random_bytes(32)

    iv, ciphertext, tag = encrypt(plaintext, key)

    save_encrypted_message(iv, ciphertext, tag, filename)

    puts "Chave em Base64 (guarde para descriptografar): #{Base64.strict_encode64(key)}"
  when 2
    puts "Informe o nome do arquivo da mensagem criptografada (ex: mensagem1.bin): "
    filename = gets.chomp

    puts "Insira a chave (em Base64): "
    key_base64 = gets.chomp
    key = Base64.strict_decode64(key_base64)

    iv, ciphertext, tag = load_encrypted_message(filename)

    if iv && ciphertext && tag
      begin
        decrypted_text = decrypt(iv, ciphertext, tag, key)
        puts "Texto descriptografado: #{decrypted_text}"
      rescue OpenSSL::Cipher::CipherError => e
        puts "Erro ao descriptografar: #{e.message}"
      end
    end
  when 3
    puts "Saindo..."
    break
  else
    puts "Opção inválida. Tente novamente."
  end
end