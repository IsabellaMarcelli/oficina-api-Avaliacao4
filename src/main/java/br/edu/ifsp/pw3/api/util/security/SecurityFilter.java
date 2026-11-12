package br.edu.ifsp.pw3.api.util.security;

import br.edu.ifsp.pw3.api.usuario.UsuarioRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// lê o JWT do cabeçalho authorization,
// valida e, se estiver ok, marca o usuário como autenticado nesta requisição.
@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuarioRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Recuperando o cabeçalho Authorization (o token JWT).
        var authorizationHeader = request.getHeader("Authorization");

        // Se o JWT foi enviado...
        if (authorizationHeader != null) {
            // Tira o 'Bearer ':
            var tokenJWT = authorizationHeader.replace("Bearer ", "");

            try {
                // Valida o token e pega o login (subject):
                var subject = tokenService.getSubject(tokenJWT);

                // Carrega o usuário com esse login do BD:
                var usuario = repository.findByLogin(subject);

                if (usuario != null) {
                    // Objeto que representa a identidade do usuário autenticado:
                    var authentication = new UsernamePasswordAuthenticationToken(usuario, null,
                            usuario.getAuthorities());

                    // Manda o Spring AUTENTICAR esse usuário (nesta requisição, não há sessão):
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (RuntimeException e) {
                // Token inválido ou expirado: o usuário NÃO é autenticado,
                // e o próprio Spring Security bloqueia a requisição (403).
                System.out.println(e.getMessage());
            }
        }

        // Segue para o próximo filtro / controller:
        filterChain.doFilter(request, response);
    }
}
