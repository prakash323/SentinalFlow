import { ArrowRight, Check } from 'lucide-react';

import { useAuth } from '../auth/AuthContext';
import RotatingWord from '../components/public/motion/RotatingWord';
import Reveal from '../components/public/Reveal';
import AlertStory from '../components/public/story/AlertStory';
import AnomalyChart from '../components/public/story/AnomalyChart';
import DashboardMockup from '../components/public/story/DashboardMockup';
import HeroStage from '../components/public/story/HeroStage';
import InvestigationStory from '../components/public/story/InvestigationStory';
import MetricsStrip from '../components/public/story/MetricsStrip';
import ModelChain from '../components/public/story/ModelChain';
import RingPanel from '../components/public/story/RingPanel';
import SignalCards from '../components/public/story/SignalCards';
import StreamVisual from '../components/public/story/StreamVisual';
import { AiBoundary, AiVisual, ArchitectureVisual, FEATURES, PipelineVisual } from '../components/public/visuals';
import { LinkButton } from '../components/ui';

/** The changing word in the hero headline. Keep them short: the box is as wide as the longest one. */
const HERO_WORDS = ['earlier.', 'faster.', 'smarter.', 'with context.'] as const;

/**
 * Public home page (no authentication), told as one scroll-driven product story:
 * hero -> event stream -> behavioral features -> anomaly detection -> alert -> investigation -> workflow -> metrics ->
 * console -> AI investigation -> platform -> architecture -> final CTA. The header and footer live in PublicLayout.
 *
 * Every claim is a real SentinelFlow capability. Numbers appear only inside visuals that are labelled
 * "Illustrative example"; there are no accuracy, volume, customer or performance figures.
 *
 * Motion: sections use <Reveal> (a one-shot scroll trigger) and the .sf-* utilities from motion.css; the scenes live in
 * components/public/story. Only the hero stage and the console mockup loop, and both can be paused.
 */
export default function Home() {
  const { isAuthenticated } = useAuth();

  return (
    <>
      {/* ------------------------------------------------ hero + product visualization */}
      <section className="pub-hero" aria-labelledby="hero-title">
        <div className="pub-container pub-hero-grid">
          <div className="pub-hero-copy">
            <p className="pub-eyebrow">AI-powered security operations</p>
            <h1 id="hero-title" className="pub-hero-title">
              <span className="sr-only">Detect threats earlier, faster, smarter and with context.</span>
              <span aria-hidden="true">
                Detect threats<br />
                <RotatingWord words={HERO_WORDS} />
              </span>
            </h1>
            <p className="pub-lede">
              SentinelFlow analyzes security events, detects behavioral anomalies, correlates alerts into incidents, and helps
              analysts investigate what matters.
            </p>
            <div className="pub-cta">
              {isAuthenticated ? (
                <LinkButton to="/dashboard" variant="primary" size="lg" icon={ArrowRight}>Open Dashboard</LinkButton>
              ) : (
                <LinkButton to="/login" variant="primary" size="lg">Get Started</LinkButton>
              )}
              <a href="#product" className="btn btn-secondary btn-lg">Explore the Platform</a>
            </div>
            <ul className="pub-hero-points">
              <li><Check size={15} aria-hidden="true" />Behavioral detection</li>
              <li><Check size={15} aria-hidden="true" />Attack classification</li>
              <li><Check size={15} aria-hidden="true" />AI-assisted investigation</li>
            </ul>
          </div>

          <Reveal className="pub-hero-visual" variant="scale"><HeroStage /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 1. event stream */}
      <section id="product" className="pub-section" aria-labelledby="product-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">The product</p>
            <h2 id="product-title" className="pub-h2">Every event becomes a signal.</h2>
            <p className="pub-lede">
              Security systems generate events. SentinelFlow streams them through Kafka, stores them and turns each one into behavioral
              context that can be scored.
            </p>
          </Reveal>
          <Reveal variant="scope"><StreamVisual /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 2. behavioral features */}
      <section id="signals" className="pub-section pub-band" aria-labelledby="signals-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">Behavioral features</p>
            <h2 id="signals-title" className="pub-h2">Signals become context.</h2>
            <p className="pub-lede">
              For every event SentinelFlow computes behavioral features and compares them with the entity's own baseline and its peer
              group, so a deviation is measured against what is normal for that entity.
            </p>
          </Reveal>
          <Reveal variant="scope"><SignalCards /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 3. anomaly detection */}
      <section id="detection" className="pub-section" aria-labelledby="detection-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">Behavioral detection</p>
            <h2 id="detection-title" className="pub-h2">
              Normal has a pattern.<br />
              SentinelFlow finds what breaks it.
            </h2>
            <p className="pub-lede">
              An ML ensemble scores every event. Normal behavior stays far below the alert threshold; when something deviates, the
              score and the factors behind it travel with the alert.
            </p>
          </Reveal>
          <div className="an-grid">
            <Reveal variant="scope"><AnomalyChart /></Reveal>
            <Reveal variant="scope" delay={120}><RingPanel /></Reveal>
          </div>
          <Reveal variant="scope" className="md-wrap">
            <p className="pub-label md-title">How a score is made</p>
            <ModelChain />
          </Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 4. alert */}
      <section id="alerts" className="pub-section pub-band" aria-labelledby="alerts-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">Alerting</p>
            <h2 id="alerts-title" className="pub-h2">From anomaly to alert.</h2>
            <p className="pub-lede">
              When a score crosses the alert policy's thresholds, SentinelFlow creates an alert with a severity, the score and the
              factors behind it. It is a record an analyst can act on, not a passing notification.
            </p>
          </Reveal>
          <Reveal variant="scope"><AlertStory /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 5. investigation */}
      <section id="investigation" className="pub-section" aria-labelledby="investigation-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">Investigation</p>
            <h2 id="investigation-title" className="pub-h2">Detected something abnormal.<br />Now understand why.</h2>
            <p className="pub-lede">
              Open the alert and the workspace assembles the evidence, the timeline and the related events, together with the model that
              scored it.
            </p>
          </Reveal>
          <Reveal variant="scope" threshold={0.25}><InvestigationStory /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 6. workflow */}
      <section id="how-it-works" className="pub-section pub-band" aria-labelledby="how-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">How it works</p>
            <h2 id="how-title" className="pub-h2">From signal to incident.</h2>
            <p className="pub-lede">
              Automated analysis turns a raw event into something an analyst can investigate. Each object links to the one before it.
            </p>
          </Reveal>
          <Reveal variant="scope" className="pub-pipeline-wrap"><PipelineVisual /></Reveal>
          <Reveal>
            <p className="pub-note">
              Related alerts are grouped into one incident per entity and event type, so analysts work from a single investigation
              context instead of many separate alerts.
            </p>
          </Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 7. metrics */}
      <section id="metrics" className="pub-section pub-section-tight" aria-labelledby="metrics-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">At a glance</p>
            <h2 id="metrics-title" className="pub-h2">One console for everything in flight.</h2>
          </Reveal>
          <Reveal variant="scope"><MetricsStrip /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------ 8. console mockup */}
      <section id="console" className="pub-section pub-band" aria-labelledby="console-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">The console</p>
            <h2 id="console-title" className="pub-h2">From overview to investigation, in one place.</h2>
            <p className="pub-lede">
              The SOC console shows event volume, anomalies, active alerts and the most anomalous entities, and opens an investigation
              from any alert.
            </p>
          </Reveal>
          <Reveal variant="scale"><DashboardMockup /></Reveal>
        </div>
      </section>

      {/* ---------------------------------------------- 9. AI investigation (dark) */}
      <section className="pub-section pub-ai theme-dark" aria-labelledby="ai-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">AI-assisted investigation</p>
            <h2 id="ai-title" className="pub-h2">From detection to understanding.</h2>
            <p className="pub-lede">
              SentinelFlow uses Spring AI to explain an incident and suggest where to look next, grounded in the evidence the platform
              has already computed.
            </p>
          </Reveal>
          <Reveal><AiVisual /></Reveal>
          <Reveal><AiBoundary /></Reveal>
        </div>
      </section>

      {/* -------------------------------------------------- 10. platform capabilities */}
      <section id="platform" className="pub-section" aria-labelledby="platform-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">Platform</p>
            <h2 id="platform-title" className="pub-h2">Everything from event to investigation.</h2>
            <p className="pub-lede">One platform covers the path from raw security events to an investigated incident.</p>
          </Reveal>
          <ul className="pub-features">
            {FEATURES.map((f, i) => (
              <li key={f.title}>
                <Reveal className="pub-feature" delay={(i % 4) * 60}>
                  <span className="pub-feature-icon"><f.icon size={20} aria-hidden="true" /></span>
                  <h3>{f.title}</h3>
                  <p>{f.text}</p>
                </Reveal>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* ------------------------------------------------------- 11. architecture */}
      <section id="architecture" className="pub-section pub-band" aria-labelledby="arch-title">
        <div className="pub-container">
          <Reveal className="pub-head">
            <p className="pub-eyebrow">Architecture</p>
            <h2 id="arch-title" className="pub-h2">Built on a real event pipeline.</h2>
            <p className="pub-lede">
              Events are stored in PostgreSQL, streamed through Kafka and scored by an ML detection service before alerts and
              incidents are created.
            </p>
          </Reveal>
          <Reveal variant="scope"><ArchitectureVisual /></Reveal>
        </div>
      </section>

      {/* ------------------------------------------------------------- 12. final CTA */}
      <section className="pub-section pub-final" aria-labelledby="final-title">
        <Reveal className="pub-container pub-final-inner">
          <h2 id="final-title" className="pub-h2">See what SentinelFlow can uncover.</h2>
          <p className="pub-lede">
            Explore security events, behavioral predictions, alerts, incidents and AI-assisted investigation in one platform.
          </p>
          <div className="pub-cta pub-cta-center">
            <LinkButton to="/dashboard" variant="primary" size="lg" icon={ArrowRight}>Open SentinelFlow</LinkButton>
            {!isAuthenticated && <LinkButton to="/login" variant="secondary" size="lg">Sign In</LinkButton>}
          </div>
        </Reveal>
      </section>
    </>
  );
}
