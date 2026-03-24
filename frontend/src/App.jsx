import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Home from './page/Home'
import ComparePackage from './page/ComparePackage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/search" element={<Home />} />
        <Route path="/compare_package" element={<ComparePackage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
