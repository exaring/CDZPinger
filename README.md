# CDZPinger

Easy-to-use ICMP ping for iOS - just create a CDZPinger and you delegate gets a callback every second with the average ping time.

This is the eXaring fork of the project with a couple of specific changes
others don't need. Don't get distracted and go for the
[original](https://github.com/cdzombak/CDZPinger) version.

## Installation

Add the dependency to your `Podfile`:

```ruby
platform :ios
pod 'CDZPinger'
...
```

Run `pod install` to install the dependencies.

## Usage

`#import "CDZPinger.h"` and:

```objc
CDZPinger *pinger = [[CDZPinger alloc] initWithHost:@"google.com"];
// keep a strong reference to pinger, maybe in a property somewhere

pinger.delegate = self;
// (assuming self is your CDZPingerDelegate)
```

In your delegate:

```objc
#pragma mark CDZPingerDelegate

- (void)pinger:(CDZPinger *)pinger didUpdate:(NSString *)sender withAverageSeconds:(NSTimeInterval)seconds
{
    NSLog([NSString stringWithFormat:@"Received ping from %@; average time %.f ms", sender, seconds*1000]);
}
```

## Requirements

`CDZPinger` requires iOS 5.x+. It might work on iOS 4, but I haven't tested it.

There's also some chance it'll work on OS X, but again, I haven't tested it there either.

## License

[MIT License](http://http://opensource.org/licenses/mit-license.php). See LICENSE for the full details.

## Developer

Chris Dzombak, with ICMP ping code from Apple sample code.

* [chris.dzombak.name](http://chris.dzombak.name/)
* chris@chrisdzombak.net
* [t@cdzombak](https://twitter.com/cdzombak)
* [a@dzombak](https://alpha.app.net/dzombak)
