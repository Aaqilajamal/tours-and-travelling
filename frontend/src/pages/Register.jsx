import React, { useState, useContext } from 'react'
import { Container, Row, Col, Form, FormGroup, Button, Spinner } from 'reactstrap'
import { Link, useNavigate } from 'react-router-dom'
import '../styles/login.css'
import registerImg from '../assets/images/login.png'
import userIcon from '../assets/images/user.png'
import { AuthContext } from '../context/AuthContext'
import { BASE_URL } from '../utils/config'

const Register = () => {
   const [credentials, setCredentials] = useState({
      username: '',
      email: '',
      password: ''
   })
   const [loading, setLoading] = useState(false)
   const [error, setError] = useState(null)

   const { dispatch } = useContext(AuthContext)
   const navigate = useNavigate()

   const handleChange = (e) => {
      setCredentials(prev => ({ ...prev, [e.target.id]: e.target.value }))
   }

   const handleClick = async (e) => {
      e.preventDefault()
      setLoading(true)
      setError(null)

      try {
         const res = await fetch(`${BASE_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
         })

         const result = await res.json()
         if (!res.ok) {
            setError(result.message)
            dispatch({ type: 'REGISTER_FAILURE' })
            return
         }

         dispatch({ type: 'REGISTER_SUCCESS' })
         navigate('/login')
      } catch (err) {
         setError(err.message)
      } finally {
         setLoading(false)
      }
   }

   return (
      <section>
         <Container>
            <Row>
               <Col lg='8' className='m-auto'>
                  <div className="login__container d-flex justify-content-between">
                     <div className="login__img">
                        <img src={registerImg} alt="Register" />
                     </div>

                     <div className="login__form">
                        <div className="user">
                           <img src={userIcon} alt="User" />
                        </div>
                        <h2>Register</h2>

                        {error && <div className="error__msg">{error}</div>}

                        <Form onSubmit={handleClick}>
                           <FormGroup>
                              <input type="text" placeholder='Username' id='username' onChange={handleChange} required />
                           </FormGroup>
                           <FormGroup>
                              <input type="email" placeholder='Email' id='email' onChange={handleChange} required />
                           </FormGroup>
                           <FormGroup>
                              <input type="password" placeholder='Password' id='password' onChange={handleChange} required />
                           </FormGroup>

                           <Button className='btn secondary__btn auth__btn' type='submit' disabled={loading}>
                              {loading ? <Spinner size="sm" /> : 'Create Account'}
                           </Button>
                        </Form>

                        <p>Already have an account? <Link to='/login'>Login</Link></p>
                     </div>
                  </div>
               </Col>
            </Row>
         </Container>
      </section>
   )
}

export default Register