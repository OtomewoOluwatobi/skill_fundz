import Link from "next/link";

export default function Home() {
  return (
    <>
      {/* Header */}
      <header className="fixed top-0 w-full bg-white/95 backdrop-blur-[10px] z-[1000] border-b border-gray-200">
        <nav className="max-w-7xl mx-auto px-5 flex justify-between items-center py-4">
          <div className="text-3xl font-bold bg-gradient-to-r from-green-600 to-purple-600 bg-clip-text text-transparent">
            SkillFund
          </div>
          <ul className="hidden md:flex list-none gap-8">
            <li><Link href="#features" className="text-gray-700 font-medium hover:text-green-600 transition-colors">How it Works</Link></li>
            <li><Link href="#entrepreneurs" className="text-gray-700 font-medium hover:text-green-600 transition-colors">For Entrepreneurs</Link></li>
            <li><Link href="#sponsors" className="text-gray-700 font-medium hover:text-green-600 transition-colors">For Sponsors</Link></li>
            <li><Link href="#about" className="text-gray-700 font-medium hover:text-green-600 transition-colors">About</Link></li>
          </ul>
          <div className="flex gap-4">
            <Link href="/signin" className="px-6 py-3 rounded-full font-semibold text-green-600 border-2 border-green-600 hover:bg-green-600 hover:text-white transition-all">
              Sign In
            </Link>
            <Link href="/signup" className="px-6 py-3 rounded-full font-semibold text-white bg-gradient-to-r from-green-600 to-purple-600 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-green-600/30 transition-all">
              Get Started
            </Link>
          </div>
        </nav>
      </header>

      <main className="bg-white text-gray-700 font-sans">
        {/* Hero Section */}
        <section
          className="pt-32 pb-16 relative overflow-hidden"
          style={{ backgroundImage: "url('/images/hero1.jpg')", backgroundSize: 'cover', backgroundPosition: 'center' }}
        >
          <div className="absolute inset-0">
            <div className="absolute top-20 left-20 w-80 h-80 bg-green-200/30 rounded-full blur-3xl"></div>
            <div className="absolute bottom-20 right-20 w-96 h-96 bg-purple-200/30 rounded-full blur-3xl"></div>
          </div>

          <div className="max-w-7xl mx-auto px-5 relative z-10">
            <div className="text-center max-w-4xl mx-auto">
              <h1 className="text-5xl lg:text-6xl font-bold leading-tight mb-6 text-gray-50">
                Empowering Dreams Through Trusted Sponsorship
              </h1>
              <p className="text-xl text-gray-50 mb-10 max-w-3xl mx-auto">
                Connect passionate entrepreneurs with forward-thinking sponsors in a secure, transparent platform that turns skill-based ideas into reality.
              </p>
              <div className="flex flex-col sm:flex-row justify-center gap-4 mb-12">
                <Link
                  href="/submit-proposal"
                  className="px-8 py-4 rounded-full font-semibold text-white bg-green-600 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-green-600/30 transition-all"
                >
                  Submit Your Proposal
                </Link>
                <Link
                  href="/become-sponsor"
                  className="px-8 py-4 rounded-full font-semibold text-green-600 border-2 border-green-600 hover:bg-green-600 hover:text-white transition-all"
                >
                  Become a Sponsor
                </Link>
              </div>

              <div className="flex flex-col md:flex-row justify-center gap-8 mt-12">
                <div className="text-center">
                  <span className="block text-4xl font-bold text-green-600">₦50M+</span>
                  <span className="text-sm text-gray-50 uppercase tracking-wide">Funded Projects</span>
                </div>
                <div className="text-center">
                  <span className="block text-4xl font-bold text-green-600">1,200+</span>
                  <span className="text-sm text-gray-50 uppercase tracking-wide">Success Stories</span>
                </div>
                <div className="text-center">
                  <span className="block text-4xl font-bold text-green-600">500+</span>
                  <span className="text-sm text-gray-50 uppercase tracking-wide">Active Sponsors</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="py-24 bg-white">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-gray-800 mb-4">Why Choose SkillFund?</h2>
              <p className="text-lg text-gray-600 max-w-3xl mx-auto">
                We've built the most secure and efficient way to connect entrepreneurial talent with funding opportunities
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 mt-16">
              <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100 hover:-translate-y-1 hover:shadow-xl transition-all">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-2xl flex items-center justify-center text-2xl mb-6">🛡️</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Admin-Controlled Escrow</h3>
                <p className="text-gray-600 leading-relaxed">Your funds are protected in our secure escrow system. Money is only released when project milestones are verified by our admin team.</p>
              </div>

              <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100 hover:-translate-y-1 hover:shadow-xl transition-all">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-2xl flex items-center justify-center text-2xl mb-6">📋</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Vetted Proposals</h3>
                <p className="text-gray-600 leading-relaxed">Every proposal goes through rigorous review to ensure quality, feasibility, and genuine impact potential before reaching sponsors.</p>
              </div>

              <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100 hover:-translate-y-1 hover:shadow-xl transition-all">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-2xl flex items-center justify-center text-2xl mb-6">🤝</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Verified Sponsors</h3>
                <p className="text-gray-600 leading-relaxed">All sponsors undergo verification to ensure legitimate funding sources and commitment to supporting grassroots entrepreneurship.</p>
              </div>

              <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100 hover:-translate-y-1 hover:shadow-xl transition-all">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-2xl flex items-center justify-center text-2xl mb-6">📊</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Real-time Tracking</h3>
                <p className="text-gray-600 leading-relaxed">Monitor project progress, funding status, and impact metrics through intuitive dashboards for complete transparency.</p>
              </div>

              <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100 hover:-translate-y-1 hover:shadow-xl transition-all">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-2xl flex items-center justify-center text-2xl mb-6">⚡</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Quick Funding</h3>
                <p className="text-gray-600 leading-relaxed">Once approved, sponsored projects receive funding quickly through our streamlined payment system with minimal delays.</p>
              </div>

              <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100 hover:-translate-y-1 hover:shadow-xl transition-all">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-2xl flex items-center justify-center text-2xl mb-6">🎯</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Impact Focused</h3>
                <p className="text-gray-600 leading-relaxed">We prioritize projects that create meaningful change in communities, ensuring every naira funded makes a difference.</p>
              </div>
            </div>
          </div>
        </section>

        {/* How It Works */}
        <section className="py-24 bg-gray-50">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-gray-800 mb-4">How It Works</h2>
              <p className="text-lg text-gray-600">Three simple steps to turn your entrepreneurial vision into funded reality</p>
            </div>

            <div className="grid md:grid-cols-3 gap-12 mt-16">
              <div className="text-center">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-6">1</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Submit Your Proposal</h3>
                <p className="text-gray-600 leading-relaxed">Create a detailed proposal outlining your skill-based project, budget requirements, timeline, and expected community impact.</p>
              </div>

              <div className="text-center">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-6">2</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Get Reviewed & Approved</h3>
                <p className="text-gray-600 leading-relaxed">Our expert team reviews your proposal for feasibility, impact potential, and alignment with our mission to support grassroots entrepreneurship.</p>
              </div>

              <div className="text-center">
                <div className="w-15 h-15 bg-gradient-to-r from-green-600 to-purple-600 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-6">3</div>
                <h3 className="text-xl font-semibold text-gray-800 mb-4">Secure Funding & Execute</h3>
                <p className="text-gray-600 leading-relaxed">Once approved, sponsors can fund your project through our secure escrow system. Receive funds as you hit verified milestones.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Trust Section */}
        <section className="py-24 bg-white">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-gray-800 mb-4">Built on Trust & Security</h2>
              <p className="text-lg text-gray-600">Your success is our priority. That's why we've implemented industry-leading security measures.</p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mt-12">
              <div className="flex items-center gap-4 p-6 bg-gray-50 rounded-2xl">
                <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center text-green-600 text-lg">🏦</div>
                <div>
                  <h4 className="font-semibold text-gray-800">Bank-Level Security</h4>
                  <p className="text-sm text-gray-600">256-bit SSL encryption protects all transactions</p>
                </div>
              </div>

              <div className="flex items-center gap-4 p-6 bg-gray-50 rounded-2xl">
                <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center text-green-600 text-lg">✅</div>
                <div>
                  <h4 className="font-semibold text-gray-800">Admin Oversight</h4>
                  <p className="text-sm text-gray-600">Every funding release requires admin verification</p>
                </div>
              </div>

              <div className="flex items-center gap-4 p-6 bg-gray-50 rounded-2xl">
                <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center text-green-600 text-lg">📱</div>
                <div>
                  <h4 className="font-semibold text-gray-800">Real-time Updates</h4>
                  <p className="text-sm text-gray-600">Instant notifications on all funding activities</p>
                </div>
              </div>

              <div className="flex items-center gap-4 p-6 bg-gray-50 rounded-2xl">
                <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center text-green-600 text-lg">💰</div>
                <div>
                  <h4 className="font-semibold text-gray-800">Secure Payments</h4>
                  <p className="text-sm text-gray-600">Multiple payment options with fraud protection</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Final CTA */}
        <section className="py-24 bg-gradient-to-r from-green-600 to-purple-600 text-white text-center">
          <div className="max-w-7xl mx-auto px-5">
            <h2 className="text-4xl font-bold mb-4">Ready to Fund the Future?</h2>
            <p className="text-xl mb-10 opacity-90">Join thousands of entrepreneurs and sponsors who are already making a difference through SkillFund</p>
            <div className="flex flex-col sm:flex-row justify-center gap-4">
              <Link href="/start-project" className="px-8 py-4 rounded-full font-semibold bg-white text-green-700 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-white/30 transition-all">
                Start Your Project Today
              </Link>
              <Link href="/explore-investments" className="px-8 py-4 rounded-full font-semibold text-white border-2 border-white hover:bg-white hover:text-green-700 transition-all">
                Explore Investment Opportunities
              </Link>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="bg-gray-800 text-white py-12">
          <div className="max-w-7xl mx-auto px-5">
            <div className="grid md:grid-cols-4 gap-8 mb-8">
              <div>
                <h3 className="mb-4 text-green-400 font-semibold">SkillFund</h3>
                <p className="text-gray-300">Empowering grassroots entrepreneurship through secure, transparent funding solutions.</p>
              </div>

              <div>
                <h3 className="mb-4 text-green-400 font-semibold">For Entrepreneurs</h3>
                <div className="space-y-2">
                  <Link href="/submit-proposal" className="block text-gray-300 hover:text-white transition-colors">Submit Proposal</Link>
                  <Link href="/success-stories" className="block text-gray-300 hover:text-white transition-colors">Success Stories</Link>
                  <Link href="/resources" className="block text-gray-300 hover:text-white transition-colors">Resources</Link>
                  <Link href="/faq" className="block text-gray-300 hover:text-white transition-colors">FAQ</Link>
                </div>
              </div>

              <div>
                <h3 className="mb-4 text-green-400 font-semibold">For Sponsors</h3>
                <div className="space-y-2">
                  <Link href="/browse-projects" className="block text-gray-300 hover:text-white transition-colors">Browse Projects</Link>
                  <Link href="/impact-reports" className="block text-gray-300 hover:text-white transition-colors">Impact Reports</Link>
                  <Link href="/sponsor-benefits" className="block text-gray-300 hover:text-white transition-colors">Sponsor Benefits</Link>
                  <Link href="/corporate-partnerships" className="block text-gray-300 hover:text-white transition-colors">Corporate Partnerships</Link>
                </div>
              </div>

              <div>
                <h3 className="mb-4 text-green-400 font-semibold">Support</h3>
                <div className="space-y-2">
                  <Link href="/help" className="block text-gray-300 hover:text-white transition-colors">Help Center</Link>
                  <Link href="/contact" className="block text-gray-300 hover:text-white transition-colors">Contact Us</Link>
                  <Link href="/security" className="block text-gray-300 hover:text-white transition-colors">Security</Link>
                  <Link href="/privacy" className="block text-gray-300 hover:text-white transition-colors">Privacy Policy</Link>
                </div>
              </div>
            </div>

            <div className="border-t border-gray-700 pt-4 text-center text-gray-400">
              <p>&copy; 2025 SkillFund. All rights reserved. | Licensed and regulated financial services.</p>
            </div>
          </div>
        </footer>
      </main>
    </>
  );
}