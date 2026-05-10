import { Link, Navigate, useParams } from 'react-router-dom';
import { PageHero } from '../components/ui/PageHero';
import { BlogHeroVisual } from '../components/ui/HeroVisuals';
import { ArrowLink } from '../components/ui/Button';
import { Section } from '../components/ui/Section';
import { CtaBanner } from '../components/CtaBanner';
import { BLOG_POSTS, type BlogPost } from '../content/resources';

function meta(post: BlogPost) {
  return `${post.category} · ${post.readTime}`;
}

export function BlogPage() {
  const [feature, ...rest] = BLOG_POSTS;

  return (
    <>
      <PageHero
        eyebrow="Blog"
        title="Field notes on machine identity, written by people who do this for a living."
        lede="Practical guides and operating-model essays for the security and platform engineers actually responsible for non-human identities. No vendor fluff."
        visual={<BlogHeroVisual />}
      />

      <Section variant="tight">
        {feature ? (
          <article className="blog-feature">
            <div className="blog-meta">{meta(feature)}</div>
            <h2>
              <Link to={`/blog/${feature.slug}`}>{feature.title}</Link>
            </h2>
            <p className="t-lede">{feature.description}</p>
            <ArrowLink to={`/blog/${feature.slug}`}>Read the post</ArrowLink>
          </article>
        ) : null}

        <div className="blog-grid u-mt-12">
          {rest.map((post) => (
            <article key={post.slug} className="blog-card">
              <div className="blog-meta">{meta(post)}</div>
              <h3>
                <Link to={`/blog/${post.slug}`}>{post.title}</Link>
              </h3>
              <p>{post.description}</p>
            </article>
          ))}
        </div>
      </Section>

      <CtaBanner
        title="Want this in your inbox?"
        body="A short, high-signal note when we publish - usually once or twice a month. Unsubscribe whenever."
        primary={{ label: 'Talk to the founder', to: '/about' }}
        secondary={{ label: 'Read the source', to: 'https://github.com/identrail/identrail' }}
      />
    </>
  );
}

export function BlogArticlePage() {
  const { slug } = useParams<{ slug: string }>();
  const post = BLOG_POSTS.find((p) => p.slug === slug);
  if (!post) return <Navigate to="/blog" replace />;

  return (
    <article className="container article">
      <header>
        <div className="article-meta">
          <span>{post.category}</span>
          <span className="dot">·</span>
          <span>{post.readTime}</span>
          <span className="dot">·</span>
          <span>By Identrail</span>
        </div>
        <h1>{post.title}</h1>
        <p className="t-lede" style={{ marginTop: 'var(--space-4)' }}>
          {post.description}
        </p>
      </header>

      {post.intro.map((p, i) => (
        <p key={`intro-${i}`}>{p}</p>
      ))}

      {post.sections.map((section) => (
        <section key={section.heading}>
          <h2>{section.heading}</h2>
          {section.paragraphs.map((p, i) => (
            <p key={`${section.heading}-${i}`}>{p}</p>
          ))}
          {section.bullets && section.bullets.length > 0 ? (
            <ul>
              {section.bullets.map((b) => (
                <li key={b}>{b}</li>
              ))}
            </ul>
          ) : null}
        </section>
      ))}

      {post.references && post.references.length > 0 ? (
        <section>
          <h2>References</h2>
          <ul>
            {post.references.map((r) => (
              <li key={r.href}>
                <a href={r.href} target="_blank" rel="noopener noreferrer">
                  {r.label}
                </a>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <footer className="article-foot">
        <ArrowLink to="/blog">Back to all posts</ArrowLink>
      </footer>
    </article>
  );
}
