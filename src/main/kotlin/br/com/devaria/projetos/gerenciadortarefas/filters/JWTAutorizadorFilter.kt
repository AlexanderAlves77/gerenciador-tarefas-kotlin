package br.com.devaria.projetos.gerenciadortarefas.filters

import br.com.devaria.projetos.gerenciadortarefas.authorization
import br.com.devaria.projetos.gerenciadortarefas.bearer
import br.com.devaria.projetos.gerenciadortarefas.models.Usuario
import br.com.devaria.projetos.gerenciadortarefas.utils.JWTUtils
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import sun.plugin.liveconnect.SecurityContextHelper
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JWTAutorizadorFilter(authenticationManager : AuthenticationManager, val jwtUtils: JWTUtils)
    : BasicAuthenticationFilter(authenticationManager) {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val athorization = request.getHeader(authorization)

        if(athorization != null && authorization.startsWith(bearer)){
            val autorizado = getAuthentication(athorization)
            SecurityContextHolder.getContext().authentication = autorizado
        }

        chain.doFilter(request, response)
    }

    private fun getAuthentication(athorization: String): UsernamePasswordAuthenticationToken {
        val token = athorization.substring(7)
        if(jwtUtils.isTokenValido(token)){
            val idString = jwtUtils.getUsuarioId(token)
            if(!idString.isNullOrBlank() && !idString.isNullOrEmpty()){
                val usuario = Usuario(idString.toLong(), "Usuário Teste", "admin@admin.com", "Admin1234@")
                return UsernamePasswordAuthenticationToken(usuario, null)
            }
        }
        throw UsernameNotFoundException("Token informado não está válido, ou não tem uma informação de identificação do usuário.")
    }
}