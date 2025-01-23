import React, { useState } from 'react';
import './Login.css';

function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();

    setErrors({
      email: '',
      password: ''
    });
    
    let hasError = false;
    
    if (!email) {
      setErrors(prevErrors => ({ ...prevErrors, email: 'L\'email est requis' }));
      hasError = true;
    } else if (!isValidEmail(email)) {
      setErrors(prevErrors => ({ ...prevErrors, email: 'Veuillez entrer un email valide' }));
      hasError = true;
    }

    if (!password) {
      setErrors(prevErrors => ({ ...prevErrors, password: 'Le mot de passe est requis' }));
      hasError = true;
    } else if (password.length < 6) {
      setErrors(prevErrors => ({ ...prevErrors, password: 'Le mot de passe doit contenir au moins 6 caractères' }));
      hasError = true;
    }

    if (!hasError) {
      simulateLogin(email, password);
    }
  };

  const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const simulateLogin = (email, password) => {
    setLoading(true);
    
    setTimeout(() => {
      setLoading(false);
      alert('Connexion réussie !');
    }, 1500);
  };

  return (
    <form id="loginForm" onSubmit={handleSubmit}>
      
      <div class="login-container">
    <div class="login-header">
        
        <h1>Login</h1>
        <p>Enter your credentials to continue</p>
    </div>
    <form id="loginForm" novalidate>
        <div class="input-group">
            <label for="email">Email</label>
            <input 
                type="email" 
                id="email" 
                name="email" 
                placeholder="youremail@example.com" 
                required
            />
            <div class="error-message" id="emailError"></div>
        </div>
        <div class="input-group">
            <label for="password">Password</label>
            <input 
                type="password" 
                id="password" 
                name="password" 
                placeholder="Your password" 
                required
            />
            <div class="error-message" id="passwordError"></div>
        </div>
        <button type="submit" class="login-button">Login</button>
        
    </form>
    <div class="form-footer">
        <img src="SKAPLINK.png" alt="Login Image" class="login-image" />
        <p><a href="#">Forgot password?</a></p>
    </div>
</div>

    </form>
  );
}

export default LoginForm;
