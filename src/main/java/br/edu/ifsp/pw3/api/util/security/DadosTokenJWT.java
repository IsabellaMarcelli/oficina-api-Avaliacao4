package br.edu.ifsp.pw3.api.util.security;

// DTO para devolver o token JWT no corpo da resposta do login (como JSON)
public record DadosTokenJWT(String token) {

}
