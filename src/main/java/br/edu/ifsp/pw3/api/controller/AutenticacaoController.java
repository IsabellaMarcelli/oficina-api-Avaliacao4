package br.edu.ifsp.pw3.api.controller;

import br.edu.ifsp.pw3.api.usuario.DadosAutenticacao;
import br.edu.ifsp.pw3.api.usuario.Usuario;
import br.edu.ifsp.pw3.api.util.security.DadosTokenJWT;
import br.edu.ifsp.pw3.api.util.security.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class AutenticacaoController {

    // Classe do Spring que dispara o processo de autenticação
    // (exportada como @Bean em SecurityConfigurations)
    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private TokenService tokenService;

    // POST /login -> 200 OK com { "token": "..." }
    @PostMapping
    public ResponseEntity<DadosTokenJWT> efetuarLogin(@RequestBody @Valid DadosAutenticacao dados) {

        var authenticationToken = new UsernamePasswordAuthenticationToken(dados.login(), dados.senha());
        var authentication = manager.authenticate(authenticationToken);

        // Criando o token JWT para o usuário autenticado:
        var tokenJWT = tokenService.gerarToken((Usuario) authentication.getPrincipal());

        return ResponseEntity.ok(new DadosTokenJWT(tokenJWT));
    }
}
