package br.edu.ifsp.pw3.api.usuario;

import jakarta.validation.constraints.NotBlank;

// Dados enviados na requisição de login
public record DadosAutenticacao(

        @NotBlank
        String login,

        @NotBlank
        String senha) {

}
